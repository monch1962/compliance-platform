class CicdGate < Formula
  desc "CI/CD compliance gate for Australian ISM and Essential Eight standards"
  homepage "https://github.com/monch1962/compliance-platform"
  version "0.3.1"
  license "Apache-2.0"

  if OS.mac? && Hardware::CPU.intel?
    url "https://github.com/monch1962/compliance-platform/releases/download/v0.3.1/cicd-gate_darwin_amd64"
    sha256 "c01441c3177acdf3c6d78d8046aca0c7e7d9c2b98afba41f4ed4de9bbf10233a"
  elsif OS.mac? && Hardware::CPU.arm?
    url "https://github.com/monch1962/compliance-platform/releases/download/v0.3.1/cicd-gate_darwin_arm64"
    sha256 "836e624eda6ff2a4dee34eedb561512f6fdfaaa2e31e9a23ada4c8d7d5ec4e7c"
  elsif OS.linux? && Hardware::CPU.intel?
    url "https://github.com/monch1962/compliance-platform/releases/download/v0.3.1/cicd-gate_linux_amd64"
    sha256 "4e7d2fed1f9be9611375411c1206db3c9f66150898976e8703b4b5a625c11213"
  elsif OS.linux? && Hardware::CPU.arm?
    url "https://github.com/monch1962/compliance-platform/releases/download/v0.3.1/cicd-gate_linux_arm64"
    sha256 "100a353105ff5bd3f56a93f95dcb94eb167f215dd8554a35fb4578b6d1691877"
  end

  def install
    bin.install Dir["cicd-gate_*"].first => "cicd-gate"
  end

  test do
    assert_match "v#{version}", shell_output("#{bin}/cicd-gate version")
  end
end
