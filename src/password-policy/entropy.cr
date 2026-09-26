module PasswordPolicy
  # Entropy of a password *policy* — not of a password someone chose.
  #
  # This distinction is the whole point, and getting it wrong is the usual way
  # these libraries mislead. `log2(alphabet ** length)` measures how much
  # entropy a policy guarantees across all passwords it admits. Applied to one
  # chosen password it measures nothing useful: "Password1234!" satisfies a
  # 12-character four-class policy and scores 78 bits, while being among the
  # first things any cracker tries.
  #
  # Judging an individual password requires estimating how *guessable* it is.
  # The CNIL names that as the better approach and then declines to set a
  # threshold for it, because the tooling is not available for French-speaking
  # users. So this shard verifies policies, and exposes `Policy#forbidden` for
  # the one practical defence against complex-but-known passwords: a denylist.
  module Entropy
    # Character classes and their sizes, as the CNIL's own worked examples
    # count them.
    UPPERCASE_SIZE = 26
    LOWERCASE_SIZE = 26
    DIGIT_SIZE     = 10

    # The recommendation is explicit: special characters must be chosen from a
    # list of at least 37. Its 12-character example only reaches 80 bits
    # because of that number.
    MINIMUM_SPECIAL_SIZE = 37

    # Entropy in bits guaranteed by `length` characters drawn from an alphabet
    # of `alphabet_size`.
    def self.of_alphabet(alphabet_size : Int32, length : Int32) : Float64
      return 0.0 if alphabet_size <= 1 || length <= 0
      length * Math.log2(alphabet_size)
    end

    # Entropy of a passphrase of `word_count` words drawn from a vocabulary of
    # `vocabulary_size`.
    #
    # The CNIL's third example — seven words — assumes a vocabulary a person
    # actually draws on, not a dictionary's full extent.
    def self.of_passphrase(word_count : Int32, vocabulary_size : Int32 = 7_000) : Float64
      return 0.0 if word_count <= 0 || vocabulary_size <= 1
      word_count * Math.log2(vocabulary_size)
    end
  end
end
