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
    def ndp_reserved=(v); self.ndp_header.ndp_reserved= v; end
    def ndp_reserved; self.ndp_header.ndp_reserved; end
    def ndp_tgt=(v); self.ndp_header.ndp_tgt= v; end
    def ndp_tgt; self.ndp_header.ndp_tgt; end
    def ndp_taddr=(v); self.ndp_header.ndp_taddr= v; end
    def ndp_taddr; self.ndp_header.ndp_taddr; end
    def ndp_tgt_readable; self.ndp_header.ndp_tgt_readable; end
    def ndp_opt_type=(v); self.ndp_header.ndp_opt_type= v; end
    def ndp_opt_type; self.ndp_header.ndp_opt_type; end
    def ndp_opt_len=(v); self.ndp_header.ndp_opt_len=v; end
    def ndp_opt_len;self.ndp_header.ndp_opt_len; end
    def ndp_lla=(v); self.ndp_header.ndp_lla=v; end
    def ndp_lla; self.ndp_header.ndp_lla; end
    def ndp_laddr=(v); self.ndp_header.ndp_laddr= v; end
    def ndp_laddr; self.ndp_header.ndp_laddr; end
    def ndp_lla_readable; self.ndp_header.ndp_lla_readable; end
    def ndp_set_flags=(v); self.ndp_header.ndp_set_flags= v; end
  end
end
