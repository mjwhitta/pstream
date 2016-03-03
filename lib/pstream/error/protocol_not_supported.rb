class PStream::Error::ProtocolNotSupported < PStream::Error
    def initialize(prot)
        super("Protocol #{prot} not supported")
    end
end
