require 'lpb/medoro/version'
require 'nori'
require 'nokogiri'

module Lpb
  module Medoro
    class Gateway
      def initialize(gateway_key_file:, merchant_key_file:, merchant_id:, key_index: 1)
        @gateway_key = OpenSSL::PKey::RSA.new(File.read(gateway_key_file))
        @merchant_key = OpenSSL::PKey::RSA.new(File.read(merchant_key_file))
        @merchant_id = merchant_id
        @key_index = key_index
      end

      def setup_purchase(data:, callback:, error_callback:)
        xml_data = prepare_data(data)
        encrypted_data = encrypt_data(xml_data)
        {
          INTERFACE: @merchant_id,
          KEY_INDEX: @key_index,
          KEY: encrypted_data[:key],
          DATA: encrypted_data[:data],
          SIGNATURE: generate_signature(xml_data),
          CALLBACK: callback,
          ERROR_CALLBACK: error_callback
        }
      end

      def parse_response(response)
        data = decrypt_data(response['DATA'], response['KEY'])
        return unless check_signature(data, response['SIGNATURE'])

        parse_xml(data)['data']
      end

      private

      def prepare_data(data)
        Nokogiri::XML::Builder.new do |xml|
          xml.data {
            xml.Payment {
              xml.Mode 3
            }
            xml.Order {
              xml.ID data[:order_id]
              xml.Amount data[:amount]
              xml.Currency data[:currency]
              xml.Description data[:description]
            }
          }
        end.to_xml
      end

      def parse_xml(data)
        Nori.new.parse(data)
      end

      def encrypt_data(data)
        cipher = OpenSSL::Cipher.new('rc4')
        cipher.encrypt
        key = cipher.random_key
        {
          data: Base64.encode64(cipher.update(data) + cipher.final),
          key: Base64.encode64(@gateway_key.public_encrypt(key))
        }
      end

      def decrypt_data(data, key)
        decipher = OpenSSL::Cipher.new('rc4')
        decipher.decrypt
        decipher.key = @merchant_key.private_decrypt(Base64.decode64(key))
        decipher.update(Base64.decode64(data)) + decipher.final
      end

      def generate_signature(data)
        Base64.encode64(@merchant_key.sign(OpenSSL::Digest::SHA1.new, data))
      end

      def check_signature(data, signature)
        @gateway_key.verify(OpenSSL::Digest::SHA1.new, Base64.decode64(signature), data)
      end
    end
  end
end
