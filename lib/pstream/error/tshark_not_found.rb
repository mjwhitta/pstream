class PStream::Error::TsharkNotFound < PStream::Error
    def initialize
        super("Please install tshark!")
    end
end
