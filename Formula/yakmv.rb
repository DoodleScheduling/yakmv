# typed: false
# frozen_string_literal: true

# This file was generated by GoReleaser. DO NOT EDIT.
class Yakmv < Formula
  desc "Kubernetes manifest validator"
  homepage "https://github.com/doodlescheduling/yakmv"
  version "0.0.3"

  on_macos do
    if Hardware::CPU.intel?
      url "https://github.com/DoodleScheduling/yakmv/releases/download/v0.0.3/yakmv_0.0.3_darwin_amd64.tar.gz"
      sha256 "186c57ce393397d9592cd45a69364dccdd87fa0965ca86b52d55b4a662d47cc0"

      def install
        bin.install "yakmv"
      end
    end
    if Hardware::CPU.arm?
      url "https://github.com/DoodleScheduling/yakmv/releases/download/v0.0.3/yakmv_0.0.3_darwin_arm64.tar.gz"
      sha256 "3936fd3736bc6dcaa0fe7ea700d849b9f5aa217beb2c235f4b5cfc302757e822"

      def install
        bin.install "yakmv"
      end
    end
  end

  on_linux do
    if Hardware::CPU.arm? && Hardware::CPU.is_64_bit?
      url "https://github.com/DoodleScheduling/yakmv/releases/download/v0.0.3/yakmv_0.0.3_linux_arm64.tar.gz"
      sha256 "44dc23ba388963497b33ba68086cb25359cc49b4c5c1c39b92f2a5cad36367c5"

      def install
        bin.install "yakmv"
      end
    end
    if Hardware::CPU.intel?
      url "https://github.com/DoodleScheduling/yakmv/releases/download/v0.0.3/yakmv_0.0.3_linux_amd64.tar.gz"
      sha256 "0399952352d3a5d3d28475b1fc6021cad39e1c3dfe34205cbf8ca98e61db64cf"

      def install
        bin.install "yakmv"
      end
    end
  end

  test do
    system "#{bin}/yakmv -h"
  end
end
