require "./use_case"
require "./violation"
require "./entropy"

module PasswordPolicy
  # A password policy: what a password must satisfy to be accepted.
  #
  # The three presets are the CNIL's own worked examples, which it states are
  # equivalent in entropy and all acceptable:
  #
  # * `.composed` — at least 12 characters with upper case, lower case, digits
  #   and special characters;
  # * `.long` — at least 14 characters with upper case, lower case and digits,
  #   no special character required;
  # * `.passphrase` — at least 7 words.
  #
  # Offering the second and third matters: forcing a special character on
  # everybody buys no entropy the fourteenth character would not, and pushes
  # users towards the predictable `Motdepasse1!`.
  struct Policy
    getter minimum_length : Int32
    getter maximum_length : Int32
    getter maximum_bytesize : Int32
    getter minimum_words : Int32
    getter special_alphabet_size : Int32
    getter use_case : UseCase
    getter? require_uppercase : Bool
    getter? require_lowercase : Bool
    getter? require_digit : Bool
    getter? require_special : Bool

    # Passwords refused outright, whatever else they satisfy.
    #
    # The 2022 revision added this: passwords that are complex by any
    # composition rule yet well known to attackers. Comparison ignores case.
    getter forbidden : Set(String)

    # A generous character ceiling, so hashing cannot be turned into a denial
    # of service by submitting a megabyte.
    DEFAULT_MAXIMUM_LENGTH = 128

    # Longest password Crystal's BCrypt accepts, in **bytes** — and bytes are
    # what matters: "Éducation" is nine characters and ten bytes, so an accented
    # passphrase reaches the ceiling sooner than its length suggests.
    #
    # 71, not the 72 usually quoted. `Crypto::Bcrypt` appends a NUL terminator
    # (`password.bytesize + 1`) and rejects anything past 72, so 72 bytes of
    # password become 73 and fail. Verified empirically: 71 hashes, 72 raises.
    #
    # Crystal *raises* where the classic C implementations silently truncate —
    # the better failure of the two, but it means a password this policy admits
    # and the hashing then refuses is a bug in the policy, not a truncated
    # secret. Argon2 and scrypt have no such ceiling; raise this if you use one.
    DEFAULT_MAXIMUM_BYTESIZE = 71

    def initialize(
      @minimum_length : Int32 = 12,
      @maximum_length : Int32 = DEFAULT_MAXIMUM_LENGTH,
      @maximum_bytesize : Int32 = DEFAULT_MAXIMUM_BYTESIZE,
      @require_uppercase : Bool = true,
      @require_lowercase : Bool = true,
      @require_digit : Bool = true,
      @require_special : Bool = true,
      @minimum_words : Int32 = 0,
      @special_alphabet_size : Int32 = Entropy::MINIMUM_SPECIAL_SIZE,
      @use_case : UseCase = UseCase::WithAccessRestriction,
      forbidden : Enumerable(String) = [] of String,
    )
      raise ArgumentError.new("minimum_length cannot be negative") if @minimum_length < 0
      if @maximum_length < @minimum_length
        raise ArgumentError.new("maximum_length is below minimum_length")
      end
      raise ArgumentError.new("maximum_bytesize must be positive") if @maximum_bytesize < 1
      raise ArgumentError.new("minimum_words cannot be negative") if @minimum_words < 0
      @forbidden = forbidden.map(&.downcase).to_set
    end

    # CNIL example 1 — 12 characters, all four classes.
    def self.composed(use_case : UseCase = UseCase::WithAccessRestriction,
                      forbidden : Enumerable(String) = [] of String) : Policy
      new(minimum_length: 12, require_special: true, use_case: use_case, forbidden: forbidden)
    end

    # CNIL example 2 — 14 characters, no special character required.
    def self.long(use_case : UseCase = UseCase::WithAccessRestriction,
                  forbidden : Enumerable(String) = [] of String) : Policy
      new(minimum_length: 14, require_special: false, use_case: use_case, forbidden: forbidden)
    end

    # CNIL example 3 — a passphrase of at least 7 words.
    #
    # No composition is imposed: a passphrase earns its entropy from word
    # count, and demanding a capital and a digit on top of it only makes it
    # harder to remember.
    def self.passphrase(minimum_words : Int32 = 7,
                        use_case : UseCase = UseCase::WithAccessRestriction,
                        forbidden : Enumerable(String) = [] of String) : Policy
      new(
        minimum_length: 0,
        require_uppercase: false, require_lowercase: false,
        require_digit: false, require_special: false,
        minimum_words: minimum_words, use_case: use_case, forbidden: forbidden
      )
    end

    # Everything wrong with `password`, in declaration order. Empty means
    # acceptable.
    def validate(password : String) : Array(Violation)
      violations = [] of Violation

      if password.empty?
        violations << Violation::Empty
        return violations
      end

      violations << Violation::Forbidden if @forbidden.includes?(password.downcase)
      check_size(password, violations)
      check_classes(password, violations)
      violations
    end

    private def check_size(password : String, violations : Array(Violation)) : Nil
      violations << Violation::TooShort if password.size < @minimum_length
      violations << Violation::TooLong if password.size > @maximum_length
      violations << Violation::TooManyBytes if password.bytesize > @maximum_bytesize
      if @minimum_words > 0 && word_count(password) < @minimum_words
        violations << Violation::TooFewWords
      end
    end

    private def check_classes(password : String, violations : Array(Violation)) : Nil
      violations << Violation::MissingUppercase if require_uppercase? && !password.matches?(/\p{Lu}/)
      violations << Violation::MissingLowercase if require_lowercase? && !password.matches?(/\p{Ll}/)
      violations << Violation::MissingDigit if require_digit? && !password.matches?(/\p{Nd}/)
      violations << Violation::MissingSpecial if require_special? && !password.matches?(/[^\p{L}\p{N}]/)
    end

    def valid?(password : String) : Bool
      validate(password).empty?
    end

    # Words are whitespace-separated runs, as a person writing a passphrase
    # would count them.
    def word_count(password : String) : Int32
      password.split(/\s+/).count { |word| !word.empty? }
    end

    # Entropy in bits this policy guarantees — the figure to compare against
    # `UseCase#minimum_entropy`.
    #
    # For a passphrase policy it is derived from the word count; otherwise from
    # the alphabet the required classes imply, raised to the minimum length.
    # Only classes the policy *requires* are counted: an optional class adds no
    # guarantee, because a password may leave it out.
    def entropy : Float64
      return Entropy.of_passphrase(@minimum_words) if @minimum_words > 0

      alphabet = 0
      alphabet += Entropy::UPPERCASE_SIZE if require_uppercase?
      alphabet += Entropy::LOWERCASE_SIZE if require_lowercase?
      alphabet += Entropy::DIGIT_SIZE if require_digit?
      alphabet += @special_alphabet_size if require_special?

      Entropy.of_alphabet(alphabet, @minimum_length)
    end

    # Whether this policy reaches the entropy its use case demands.
    #
    # Worth asserting in your own test suite: it turns a claim of compliance
    # into something that fails a build when someone loosens the policy.
    def satisfies_use_case? : Bool
      entropy >= @use_case.minimum_entropy
    end
  end
end
