# frozen_string_literal: true

# Checks the LFCP-WIRE-01 CDDL with the reference cddl tool (cabo/cddl):
#
# 1. wire/LFCP-WIRE-01.cddl plus wire/LFCP-WIRE-01.supplement.cddl compile as
#    one schema with no undefined names (undefined names of the extracted
#    file alone are listed for information);
# 2. every rule restated in wire/LFCP-WIRE-01.summary.cddl (Part XXVIII)
#    agrees with the body definition: instances generated from either side
#    validate against the other;
# 3. every fixture in wire/fixtures/manifest.json validates (or fails, when
#    the manifest says so) against its rule.
#
# Run with: bundle exec ruby scripts/check-cddl.rb

require "json"
require "timeout"
require "cddl"
require "cbor-pure"
require "cbor-diag-parser"

ROOT = File.expand_path("..", __dir__)
BODY = File.read(File.join(ROOT, "wire/LFCP-WIRE-01.cddl"))
SUPPLEMENT = File.read(File.join(ROOT, "wire/LFCP-WIRE-01.supplement.cddl"))
SUMMARY = File.read(File.join(ROOT, "wire/LFCP-WIRE-01.summary.cddl"))
SCHEMA = "#{BODY}\n#{SUPPLEMENT}"
GENERATED_PER_RULE = 25
# The tool's validator can backtrack exponentially on a non-matching instance
# with long generated arrays; a rule that takes longer counts as disagreeing.
AGREEMENT_TIMEOUT_SECONDS = 20

$failures = 0
def fail!(message)
  $failures += 1
  puts "FAIL  #{message}"
end

def rule_names(text)
  text.scan(/^([A-Za-z@_$][A-Za-z0-9@_$.-]*)\s*(?:<[^>]*>)?\s*=/).flatten.uniq
end

# The cddl tool validates against the first rule of the schema, and parsing
# a schema takes seconds. RootedParser parses once and can then use any type
# rule as the root, by presenting that rule first to the tool's rule walk.
class RootedParser < CDDL::Parser
  def with_root(name)
    @root_name = name
    self
  end

  def ast
    @root_name ? RootFirst.new(super, @root_name) : super
  end

  # Wraps the parse tree so `each(:rule)` yields the chosen root rule first.
  class RootFirst
    def initialize(ast, root_name)
      @ast = ast
      @root_name = root_name
    end

    def each(name = nil, &block)
      return @ast.each(name, &block) unless name == :rule

      nodes = []
      @ast.each(:rule) { |rule| nodes << rule }
      first, rest = nodes.partition { |rule| rule.typename.to_s == @root_name }
      raise "no type rule named #{@root_name}" if first.empty?

      (first + rest).each(&block)
    end
  end
end

PARSERS = Hash.new { |h, schema| h[schema] = RootedParser.new(schema) }

def parser_for(schema, target)
  PARSERS[schema].with_root(target)
end

# Compiles `schema` with every rule reachable from the root and returns the
# names the tool reports as undefined (each is stubbed so the next one shows).
def undefined_names(schema)
  names = rule_names(schema).reject { |n| schema =~ /^#{Regexp.escape(n)}\s*</ }
  stubs = []
  loop do
    text = "lfcp-check-root = [#{names.join(', ')}]\n#{schema}\n#{stubs.map { |s| "#{s} = any" }.join("\n")}"
    begin
      CDDL::Parser.new(text).rules
      return stubs
    rescue RuntimeError => e
      name = e.message[/Unknown (?:type|group) (\S+)/, 1]
      raise unless name && !stubs.include?(name)
      stubs << name
    end
  end
end

def silence_warnings
  old = $stderr
  $stderr = File.open(File::NULL, "w")
  yield
ensure
  $stderr = old
end

def decode(source)
  bytes = if source.key?("hex")
            [source["hex"]].pack("H*")
          else
            parsed = CBOR_DIAGParser.new.parse(File.read(File.join(ROOT, "wire/fixtures", source["diag"])).b)
            raise "cannot parse #{source['diag']}" unless parsed
            CBOR.encode(parsed.to_rb)
          end
  bytes = [source["prefix_hex"]].pack("H*") + bytes if source["prefix_hex"]
  CBOR.decode(bytes)
end

silence_warnings do
  # 1. Compile.
  before = undefined_names(BODY)
  after = undefined_names(SCHEMA)
  puts "cddl: extracted rules #{rule_names(BODY).size}, supplement rules #{rule_names(SUPPLEMENT).size}, " \
       "summary rules #{rule_names(SUMMARY).size}"
  puts "cddl: undefined names in extracted CDDL alone: #{before.empty? ? 'none' : before.join(', ')}"
  if after.empty?
    puts "ok    extracted + supplement compile with no undefined names"
  else
    fail! "undefined names after supplement: #{after.join(', ')}"
  end
  summary_undefined = undefined_names(SUMMARY)
  fail! "summary has undefined names: #{summary_undefined.join(', ')}" unless summary_undefined.empty?

  # 2. Summary agreement.
  srand(1)
  shared = rule_names(SUMMARY) & rule_names(SCHEMA)
  mismatches = shared.filter_map do |name|
    body = parser_for(SCHEMA, name)
    summary = parser_for(SUMMARY, name)
    disagree = begin
      Timeout.timeout(AGREEMENT_TIMEOUT_SECONDS) do
        GENERATED_PER_RULE.times.any? do
          !summary.validate(body.generate, false) || !body.validate(summary.generate, false)
        end
      end
    rescue Timeout::Error
      true
    end
    name if disagree
  end
  only_summary = rule_names(SUMMARY) - rule_names(SCHEMA)
  fail! "summary defines rules missing from the body: #{only_summary.join(', ')}" unless only_summary.empty?
  if mismatches.empty?
    puts "ok    summary agrees with body for #{shared.size} restated rules " \
         "(#{GENERATED_PER_RULE} generated instances each way)"
  else
    fail! "summary disagrees with body for: #{mismatches.join(', ')}"
  end

  # 3. Fixtures.
  manifest = JSON.parse(File.read(File.join(ROOT, "wire/fixtures/manifest.json")))
  vectors = JSON.parse(File.read(File.join(ROOT, "test-vectors/lfcp-wire-01/LFCP-TEST-VECTORS-01.json")))
  cases = vectors["cases"].to_h { |c| [c["id"], c] }
  manifest["fixtures"].each do |f|
    source = f["source"]
    label = source["case"] ? "#{source['case']}.#{source['field']}" : source["diag"]
    if source["case"]
      value = cases.dig(source["case"], source.fetch("from", "expected"), source["field"])
      unless value
        fail! "#{label}: no such vector value"
        next
      end
      source = source.merge("hex" => value["hex"])
    end
    valid = !!parser_for(SCHEMA, f["rule"]).validate(decode(source), false)
    expected = f["expect"] == "pass"
    status = valid == expected ? "ok  " : "FAIL"
    $failures += 1 unless valid == expected
    puts "#{status}  #{f['rule']} <- #{label}: #{valid ? 'valid' : 'invalid'} (expected #{f['expect']})"
  end
end

puts "cddl: #{$failures} failure(s)"
exit($failures.zero? ? 0 : 1)
