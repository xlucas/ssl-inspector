require 'cipher/cipher_suites'
require 'cipher/cipher_strings'

module Cipher

  def get_cipher_suite(cipher_suite)
    return CIPHER_SUITES[cipher_suite]
  end

   def get_cipher_suites(cipher_string)
     return CIPHER_STRINGS[cipher_string]
   end

end