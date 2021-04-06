require 'digest/md5'

	module Jekyll
	  module KeyFilter
	    def title_md5(title)
	      "#{hash(title)}"
	    end

	    private :hash

	    def hash(title)
	      Digest::MD5.hexdigest(title)
	    end
	  end
	end

	Liquid::Template.register_filter(Jekyll::KeyFilter)