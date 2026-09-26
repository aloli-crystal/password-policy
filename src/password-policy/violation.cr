module PasswordPolicy
  # Why a password was refused.
  #
  # Returned as values rather than sentences: the message a user reads belongs
  # to the application, which knows its own tone and its own languages. The
  # module this one was extracted from returned hardcoded French strings, which
  # is precisely what stopped it being reusable.
  enum Violation
    Empty
    TooShort
    TooLong
    TooManyBytes
    MissingUppercase
    MissingLowercase
    MissingDigit
    MissingSpecial
    TooFewWords
    Forbidden

    # A stable key for looking up a translation.
    def i18n_key : String
      "password_policy.#{to_s.underscore}"
    end
  end
end
