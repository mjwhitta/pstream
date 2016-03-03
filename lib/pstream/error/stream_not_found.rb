class PStream::Error::StreamNotFound < PStream::Error
    def initialize(stream, prot = "tcp")
        super("Protocol #{prot} does not have stream #{stream}")
    end
end
