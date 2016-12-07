module PacketFu
  # This Mixin simplifies access to the NDPHeaders. Mix this in with your
  # packet interface, and it will add methods that essentially delegate to
  # the 'ndp_header' method (assuming that it is a NDPHeader object)
  module NDPHeaderMixin
    def ndp_type=(v); self.ndp_header.ndp_type= v; end
    def ndp_type; self.ndp_header.ndp_type; end
    def ndp_code=(v); self.ndp_header.ndp_code= v; end
    def ndp_code; self.ndp_header.ndp_code; end
    def ndp_sum=(v); self.ndp_header.ndp_sum= v; end
    def ndp_sum; self.ndp_header.ndp_sum; end
    def ndp_sum_readable; self.ndp_header.ndp_sum_readable; end
  end
end
