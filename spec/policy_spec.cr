require "./spec_helper"

describe PasswordPolicy::Policy do
  describe "CNIL worked examples" do
    # The recommendation states these three are equivalent in entropy and all
    # acceptable. The arithmetic below is the check that they are what this
    # shard actually builds.
    it "example 1 — 12 characters, four classes" do
      policy = PasswordPolicy::Policy.composed
      policy.minimum_length.should eq(12)
      policy.require_special?.should be_true
      policy.valid?("Comptabilit3!").should be_true
    end

    it "example 2 — 14 characters, no special required" do
      policy = PasswordPolicy::Policy.long
      policy.minimum_length.should eq(14)
      policy.require_special?.should be_false
      policy.valid?("Comptabilite12").should be_true
      # A special character is allowed, simply not demanded.
      policy.valid?("Comptabilite1!").should be_true
    end

    it "example 3 — a passphrase of seven words" do
      policy = PasswordPolicy::Policy.passphrase
      policy.valid?("le petit chat boit du lait tiede").should be_true
      policy.valid?("le petit chat boit du lait").should be_false
    end

    it "imposes no composition on a passphrase" do
      # Demanding a capital and a digit on top of seven words only makes it
      # harder to remember, for entropy the words already provide.
      policy = PasswordPolicy::Policy.passphrase
      policy.require_uppercase?.should be_false
      policy.require_digit?.should be_false
      policy.require_special?.should be_false
    end
  end

  describe "entropy of the policy" do
    it "derives it from the required classes and the minimum length" do
      # 26 + 26 + 10 + 37 = 99 characters, to the twelfth power.
      PasswordPolicy::Policy.composed.entropy.should be_close(79.6, 0.1)
      # 26 + 26 + 10 = 62 characters, to the fourteenth.
      PasswordPolicy::Policy.long.entropy.should be_close(83.4, 0.1)
      PasswordPolicy::Policy.passphrase.entropy.should be_close(89.4, 0.1)
    end

    # An optional class guarantees nothing, because a password may omit it.
    it "counts only the classes it requires" do
      lax = PasswordPolicy::Policy.new(minimum_length: 12, require_special: false)
      lax.entropy.should be < PasswordPolicy::Policy.composed.entropy
    end

    it "is zero when nothing is required" do
      PasswordPolicy::Policy.new(
        minimum_length: 0, require_uppercase: false, require_lowercase: false,
        require_digit: false, require_special: false
      ).entropy.should eq(0.0)
    end
  end

  describe "use-case tiers" do
    it "publishes the CNIL entropy minimums" do
      PasswordPolicy::UseCase::Alone.minimum_entropy.should eq(80.0)
      PasswordPolicy::UseCase::WithAccessRestriction.minimum_entropy.should eq(50.0)
      PasswordPolicy::UseCase::WithDeviceHeld.minimum_entropy.should eq(13.0)
    end

    it "defaults to the tier that assumes online attacks are limited" do
      PasswordPolicy::Policy.composed.use_case.should eq(PasswordPolicy::UseCase::WithAccessRestriction)
    end

    it "confirms all three examples clear the 50-bit tier" do
      [
        PasswordPolicy::Policy.composed,
        PasswordPolicy::Policy.long,
        PasswordPolicy::Policy.passphrase,
      ].each(&.satisfies_use_case?.should(be_true))
    end

    # Worth pinning rather than smoothing over. 26 + 26 + 10 + 37 = 99, and
    # 12 × log2(99) = 79.6 — a rounding short of the 80 bits the CNIL states
    # for this example. Inflating the special alphabet to make it pass would
    # be arranging the arithmetic to fit the conclusion.
    it "shows CNIL example 1 landing just under the 80-bit tier" do
      policy = PasswordPolicy::Policy.composed(PasswordPolicy::UseCase::Alone)
      policy.entropy.should be < 80.0
      policy.satisfies_use_case?.should be_false
    end

    it "clears the 80-bit tier with a longer password or a passphrase" do
      PasswordPolicy::Policy.long(PasswordPolicy::UseCase::Alone)
        .satisfies_use_case?.should be_true
      PasswordPolicy::Policy.passphrase(use_case: PasswordPolicy::UseCase::Alone)
        .satisfies_use_case?.should be_true
    end

    it "clears the 80-bit tier with a wider special alphabet" do
      PasswordPolicy::Policy.new(minimum_length: 12, special_alphabet_size: 40,
        use_case: PasswordPolicy::UseCase::Alone).satisfies_use_case?.should be_true
    end

    it "names the measures each tier assumes" do
      PasswordPolicy::UseCase::WithAccessRestriction.required_measures.should contain("CAPTCHA")
      PasswordPolicy::UseCase::WithDeviceHeld.required_measures.should contain("three")
    end
  end

  describe "validation" do
    it "accepts a password meeting every rule" do
      PasswordPolicy::Policy.composed.validate("Comptabilit3!").should be_empty
    end

    it "reports an empty password and stops there" do
      PasswordPolicy::Policy.composed.validate("").should eq([PasswordPolicy::Violation::Empty])
    end

    it "reports every failing rule at once, not just the first" do
      violations = PasswordPolicy::Policy.composed.validate("abc")
      violations.should contain(PasswordPolicy::Violation::TooShort)
      violations.should contain(PasswordPolicy::Violation::MissingUppercase)
      violations.should contain(PasswordPolicy::Violation::MissingDigit)
      violations.should contain(PasswordPolicy::Violation::MissingSpecial)
      violations.should_not contain(PasswordPolicy::Violation::MissingLowercase)
    end

    it "reports each missing class separately" do
      policy = PasswordPolicy::Policy.composed
      policy.validate("comptabilit3!").should eq([PasswordPolicy::Violation::MissingUppercase])
      policy.validate("COMPTABILIT3!").should eq([PasswordPolicy::Violation::MissingLowercase])
      policy.validate("Comptabilite!").should eq([PasswordPolicy::Violation::MissingDigit])
      policy.validate("Comptabilite3").should eq([PasswordPolicy::Violation::MissingSpecial])
    end

    # BCrypt silently truncates past 72 bytes, so anything longer is partly
    # decorative rather than stronger.
    it "refuses a password past what the hashing can carry" do
      policy = PasswordPolicy::Policy.composed
      policy.validate("A1!" + "a" * 100).should contain(PasswordPolicy::Violation::TooManyBytes)
    end

    # The trap this shard exists to encode: the BCrypt limit is 72 *bytes*.
    # 40 accented characters are 80 bytes, so a passphrase well under any
    # character limit is already being truncated.
    it "measures the hashing limit in bytes, not characters" do
      accented = "Éé" * 20 # 40 characters, 80 bytes
      accented.size.should eq(40)
      accented.bytesize.should eq(80)

      violations = PasswordPolicy::Policy.new(minimum_length: 0,
        require_uppercase: false, require_lowercase: false,
        require_digit: false, require_special: false).validate(accented)

      violations.should contain(PasswordPolicy::Violation::TooManyBytes)
      violations.should_not contain(PasswordPolicy::Violation::TooLong)
    end

    it "allows the byte limit to be raised for hashing without one" do
      long = "A1!" + "a" * 100
      PasswordPolicy::Policy.new(maximum_length: 200, maximum_bytesize: 1024)
        .validate(long).should be_empty
    end

    it "caps characters as well, so hashing cannot be flooded" do
      PasswordPolicy::Policy.new(maximum_bytesize: 100_000)
        .validate("A1!" + "a" * 500).should contain(PasswordPolicy::Violation::TooLong)
    end

    it "accepts accented capitals as uppercase" do
      # `\p{Lu}` rather than `A-Z`: É is a capital, and here the only one.
      PasswordPolicy::Policy.composed.validate("Éducation12!").should be_empty
    end

    it "counts characters, not bytes" do
      # "Éducation12!" is 12 characters and 13 bytes; the rule is on characters.
      "Éducation12!".size.should eq(12)
      "Éducation12!".bytesize.should eq(13)
      PasswordPolicy::Policy.composed.validate("Éducation12!")
        .should_not contain(PasswordPolicy::Violation::TooShort)
    end
  end

  # The 2022 revision added this: passwords complex by any composition rule,
  # yet among the first an attacker tries.
  describe "denylist" do
    it "refuses a listed password however complex it looks" do
      policy = PasswordPolicy::Policy.composed(forbidden: ["Motdepasse1!"])
      policy.validate("Motdepasse1!").should contain(PasswordPolicy::Violation::Forbidden)
    end

    it "ignores case when comparing" do
      policy = PasswordPolicy::Policy.composed(forbidden: ["MotDePasse1!"])
      policy.validate("motdepasse1!").should contain(PasswordPolicy::Violation::Forbidden)
    end

    it "lets anything else through" do
      policy = PasswordPolicy::Policy.composed(forbidden: ["Motdepasse1!"])
      policy.validate("Comptabilit3!").should be_empty
    end
  end

  describe "construction" do
    it "refuses a maximum below the minimum" do
      expect_raises(ArgumentError, /below minimum_length/) do
        PasswordPolicy::Policy.new(minimum_length: 20, maximum_length: 10)
      end
    end

    it "refuses negative bounds" do
      expect_raises(ArgumentError, /minimum_length cannot be negative/) do
        PasswordPolicy::Policy.new(minimum_length: -1)
      end
      expect_raises(ArgumentError, /minimum_words cannot be negative/) do
        PasswordPolicy::Policy.new(minimum_words: -1)
      end
      expect_raises(ArgumentError, /maximum_bytesize must be positive/) do
        PasswordPolicy::Policy.new(maximum_bytesize: 0)
      end
    end
  end

  describe "word counting" do
    it "counts whitespace-separated runs" do
      policy = PasswordPolicy::Policy.passphrase
      policy.word_count("le petit chat").should eq(3)
      policy.word_count("  le   petit  chat  ").should eq(3)
      policy.word_count("").should eq(0)
    end
  end
end

describe PasswordPolicy::Violation do
  # Messages belong to the application, which knows its own languages. The
  # module this was extracted from returned hardcoded French sentences, and
  # that is what stopped it being reusable.
  it "offers a stable key for translation rather than a sentence" do
    PasswordPolicy::Violation::MissingUppercase.i18n_key
      .should eq("password_policy.missing_uppercase")
    PasswordPolicy::Violation::TooFewWords.i18n_key
      .should eq("password_policy.too_few_words")
  end
end

describe PasswordPolicy::Entropy do
  it "computes entropy from an alphabet and a length" do
    PasswordPolicy::Entropy.of_alphabet(62, 14).should be_close(83.4, 0.1)
    PasswordPolicy::Entropy.of_alphabet(1, 10).should eq(0.0)
    PasswordPolicy::Entropy.of_alphabet(62, 0).should eq(0.0)
  end

  it "computes entropy from a word count" do
    PasswordPolicy::Entropy.of_passphrase(7).should be_close(89.4, 0.1)
    PasswordPolicy::Entropy.of_passphrase(0).should eq(0.0)
  end

  it "records the minimum special alphabet the CNIL requires" do
    PasswordPolicy::Entropy::MINIMUM_SPECIAL_SIZE.should eq(37)
  end
end
