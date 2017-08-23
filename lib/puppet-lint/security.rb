# Defines helper methods for check plugins
class PuppetLint::CheckPlugin

  # This types represent valid values for variables and parameters
  VALID_CONTENT_TOKENS=[:NAME,:FUNCTION_NAME,:SSTRING,:STRING,:NUMBER,:TRUE,:FALSE,:DQPRE,:DQMID,:DQPOST,:VARIABLE]

  # Checks if given resource is defined in given class or define
  #
  # @param resource [Hash] puppet-lint resource_index hash
  # @param class_or_define [Hash] puppet-lint class_index or defined_type_index hash
  # @return [Boolean] it is defined inside or not
  def resource_in_class_or_define?(resource,class_or_define)
    resource[:start] > class_or_define[:start] and
      resource[:end] < class_or_define[:end]
  end

  # Checks if given parameter of a puppet resource is an array
  #
  # @param tokens [Array] puppet-lint token objects
  # @param parameter [String] search only mathing parameters
  # @return [Boolean] it is an array or not
  def value_is_array?(tokens,parameter)
    values_with_lbracks=tokens.find_all do |token|
      #  match 'parameter => ['
      token.type == :LBRACK and
        token.prev_code_token.type == :FARROW and
        token.prev_code_token.prev_code_token.value == parameter
    end
    not values_with_lbracks.empty?
  end

  # Get array of tokens for given parameter out of puppet resource definition
  #
  # @param tokens [Array] puppet-lint token objects
  # @param parameter [String] search only mathing parameters
  # @return [Array] an array of matching token objects
  def get_array_tokens_for_parameter(tokens,parameter)
    get_tokens_between(tokens,:BRACK,parameter).reject do |token|
      token.type == :COMMA
    end
  end

  # Get array of tokens with given parameter out of a hash
  #
  # @param tokens [Array] puppet-lint token objects
  # @param parameter [String] search only mathing parameters
  # @return [Array] an array of matching token objects
  def get_hash_tokens_for_parameter(tokens,parameter)
    get_tokens_between(tokens,:BRACE,parameter)
  end

  # Get array of tokens with given parameter out of any puppet block
  #
  # @param tokens [Array] puppet-lint token objects
  # @param parameter [String] search only mathing parameters
  # @return [Array] an array of matching token objects
  def get_tokens_between(tokens,type,parameter)
    brace_open=tokens.find do |token|
      token.type == left(type) and
        # Vorher kommt ein Pfeil, somit ist es der  Wert eines Parmeters
        token.prev_code_token.type == :FARROW and
        # Vor dem Pfeil kommt der gesuchte Parameter
        token.prev_code_token.prev_code_token.value == parameter
    end

    if brace_open.nil?
      return []
    else
      return get_block_between(type,brace_open)
    end
  end

  # Get resource block for given puppet resource name.
  # Resource type is irrelevant
  #
  # @param resource_title [String] resource title of queried resource block
  # @param token [PuppetLint::Lexer::Token] Token of a puppet resource
  # @return [Array] an array of array with matching token objects
  def get_resource_block_for(resource_title,token)
      titles=title_tokens_with_block

      titles.find_all do | hash |
        hash[:title].value == resource_title
      end.first.values.flatten

  end

  # Get array of tokens with values of given parameter
  #
  # @param tokens [Array] puppet-lint token objects
  # @param parameter [String] search only mathing parameters
  # @return [Array] an array of matching token objects
  def get_value_token_for_parameter(tokens,parameter)
    value_starts_tokens=tokens.find_all do |token|
      VALID_CONTENT_TOKENS.include? token.type and
        # An arrow first indicates the value of a parameter
        token.prev_code_token.type == :FARROW and
        # The given parameter comes first, then the arrow
        token.prev_code_token.prev_code_token.value == parameter
    end
    value_starts_tokens.map do |token|
      if token.type==:DQPRE
        t=[]
        until token.type == :DQPOST
          t << token
          token=token.next_code_token
        end
        t
      else
        token
      end
    end.flatten
  end

  # Get array of tokens with arguments of a puppet-function
  #
  # @param tokens [Array] puppet-lint token objects
  # @param function [String] search only mathing functions
  # @return [Array] an array of matching token objects
  def get_argument_token_for_function(tokens,function)
    lparen=tokens.find do |token|
      token.type == :LPAREN and
        token.prev_code_token.type == :FUNCTION_NAME and
        token.prev_code_token.value == function
    end

    if lparen.nil?
      return []
    else
      return get_block_between(:PAREN,lparen)
    end
  end

  # Get first token with begin of value to a given parameter token
  #
  # @param token [PuppetLint::Lexer::Token] Token of a parameter to a puppet resource
  # @return [PuppetLint::Lexer::Token] Token with value (first token after equals
  def get_variable_value_for(token)
    if token.type == :VARIABLE and token.next_code_token.type == :EQUALS
      token=token.next_code_token
      until token.next_code_token.nil? or VALID_CONTENT_TOKENS.include? token.type or token.type == :VARIABLE
        token=token.next_code_token
      end
      return token
    else
      return nil
    end
  end

  # Get Hash of titles and tokens of puppet manifest
  #
  # @return [Array] of [Hashes] with title as [PuppetLint::Lexer::Token] token
  #         and array of token with parameters as [PuppetLint::Lexer::Token]
  def title_tokens_with_block

    # Get all token blocks having between colon and semic or rbrace
    title_tokens.map do |block_starter|
      token_array=[]
      t = block_starter.next_token

      until [:SEMIC,:RBRACE].include? t.type
        token_array << t
        t = t.next_token
      end

      {
        :title   => block_starter,
        :tokens  => token_array
      }

    end

  end

  # Get resource title for rule
  #
  # @param [Hash] representing a resource_index
  # @return [String] resource title of given rule
  def get_resource_title_for(rule)
    title_token=title_tokens_with_block.find do |h|
      h[:tokens].first == rule[:tokens].first
    end
    title_token[:title] unless title_token.nil?
  end


  # Warps puppet-lint notify and generates notifies for array of problems
  #
  # @param hash [Hash] Hash with options
  # @option hash [Array] :result Array of PuppetLint::Lexer::Token containing problems
  # @option hash [Symbol] :severity Severity of problem (:warning or :critical)
  # @option hash [String] :message Description of problem
  #
  # @return nothing
  def bulk_notify(hash)
    hash[:result].each do |v|
      notify hash[:severity], {
        :message => hash[:message],
        :line    => v.line,
        :column  => v.column,
      }
    end
  end

  # Wrapper to check logic. Searches tokens matching given puppet resource or class.
  #
  # @param hash [Hash] Hash with options
  # @option hash [Array] :resource_type Array of PuppetLint::Lexer::Token containing problems
  # @option hash [Symbol] :severity Severity of problem (:warning or :critical)
  # @option hash [String] :message Description of problem
  #
  # @return nothing
  def check_resource_index(hash)

    # Operate on arrays
    unless hash[:resource_type].is_a? Array
      resource_types=[hash[:resource_type]]
    else
      resource_types=hash[:resource_type]
    end

    rules=resource_indexes.find_all do |resource|
      # Need to search resource titles, when not a predefined puppet resource
      if resource[:type].type == :CLASS
         resource_titles = title_tokens.map { |t| t.value }
         diff_titles = (resource_types - resource_titles)

         # Difference is smaler then original
         # so some elements where substracted
         diff_titles.count < resource_types.count
      else
        resource_types.include? resource[:type].value
      end
    end

    result=rules.map do |rule|
      yield rule
    end.flatten.compact

    bulk_notify(hash.merge(:result => result))

  end

  private

  # Get array of tokens between braces
  #
  # @param type [Symbol] Caps symbol representing type of brace (:BRACE, :BRACK, :PAREN)
  # @param start_token [PuppetLint::Lexer::Token] Token with opening brace
  # @return [Array] an array of matching token objects
  def get_block_between(type,start_token)
    token_array=[]
    t = start_token.next_code_token
    brack_counter=1
    until brack_counter==0
      brack_counter -= 1 if t.next_code_token.type == right(type)
      brack_counter += 1 if t.next_code_token.type == left(type)
      token_array << t
      t = t.next_code_token
    end
    return token_array
  end

  # Converts brace symbol to left/opening brace (prefixes 'L')
  #
  # @param type [Symbol] Caps symbol representing type of brace (:BRACE, :BRACK, :PAREN)
  # @return [Symbol] Caps symbol with prefixed 'L'
  def left(type)
    ("L"+type.to_s).to_sym
  end

  # Converts brace symbol to right/closing brace (prefixes 'R')
  #
  # @param type [Symbol] Caps symbol representing type of brace (:BRACE, :BRACK, :PAREN)
  # @return [Symbol] Caps symbol with prefixed 'R'
  def right(type)
    ("R"+type.to_s).to_sym
  end

end
