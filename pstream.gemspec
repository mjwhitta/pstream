Gem::Specification.new do |s|
    s.name = "pstream"
    s.version = "0.2.7"
    s.date = Time.new.strftime("%Y-%m-%d")
    s.summary = "Summarize or extract info from pcap files"
    s.description =
        "This ruby gem will summarize or extract info from pcap " \
        "files."
    s.authors = [ "Miles Whittaker" ]
    s.email = "mjwhitta@gmail.com"
    s.executables = Dir.chdir("bin") do
        Dir["*"]
    end
    s.files = Dir["lib/**/*.rb"]
    s.homepage = "https://mjwhitta.github.io/pstream"
    s.license = "GPL-3.0"
    s.add_development_dependency("rake", "~> 10.5", ">= 10.5.0")
    s.add_runtime_dependency("hilighter", "~> 1.0", ">= 1.0.0")
    s.add_runtime_dependency("scoobydoo", "~> 0.1", ">= 0.1.4")
end
