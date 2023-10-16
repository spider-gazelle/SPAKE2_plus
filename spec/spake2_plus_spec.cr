require "./spec_helper"

module SPAKE2Plus
  describe SPAKE2Plus do
    it "works against SPAKE2+-P256-SHA256-HKDF draft-01 Test Vector 1" do
      context = "SPAKE2+-P256-SHA256-HKDF draft-01"
      w0 = BigInt.new("e6887cf9bdfb7579c69bf47928a84514b5e355ac034863f7ffaf4390e67d798c", base: 16)
      w1 = BigInt.new("24b5ae4abda868ec9336ffc3b78ee31c5755bef1759227ef5372ca139b94e512", base: 16)
      l = "0495645cfb74df6e58f9748bb83a86620bab7c82e107f57d6870da8cbcb2ff9f7063a14b6402c62f99afcb9706a4d1a143273259fe76f1c605a3639745a92154b9".hexbytes
      x = BigInt.new("5b478619804f4938d361fbba3a20648725222f0a54cc4c876139efe7d9a21786", base: 16)
      y = BigInt.new("766770dad8c8eecba936823c0aed044b8c3c4f7655e8beec44a15dcbcaf78e5e", base: 16)
      share_p = "04a6db23d001723fb01fcfc9d08746c3c2a0a3feff8635d29cad2853e7358623425cf39712e928054561ba71e2dc11f300f1760e71eb177021a8f85e78689071cd".hexbytes
      share_v = "04390d29bf185c3abf99f150ae7c13388c82b6be0c07b1b8d90d26853e84374bbdc82becdb978ca3792f472424106a2578012752c11938fcf60a41df75ff7cf947".hexbytes

      ke = "ea3276d68334576097e04b19ee5a3a8b".hexbytes
      h_ay = "71d9412779b6c45a2c615c9df3f1fd93dc0aaf63104da8ece4aa1b5a3a415fea".hexbytes
      h_bx = "095dc0400355cc233fde7437811815b3c1524aae80fd4e6810cf531cf11d20e3".hexbytes

      algorithm = SPAKE2Plus::Algorithms.new(Curve::P256, OpenSSL::Algorithm::SHA256, MAC::HMAC)

      prover = Protocol.new(
        algorithm: algorithm,
        context: context,
        random: x,
        w0: w0
      )

      verifier = Protocol.new(
        algorithm: algorithm,
        context: context,
        random: y,
        w0: w0
      )

      prover.compute_x.should eq share_p
      verifier.compute_y.should eq share_v

      result = prover.compute_secret_and_verifiers_from_y(w1, share_p, share_v)
      result[0].should eq ke
      result[1].should eq h_ay
      result[2].should eq h_bx

      result = verifier.compute_secret_and_verifiers_from_x(l, share_p, share_v)
      result[0].should eq ke
      result[1].should eq h_ay
      result[2].should eq h_bx

      algorithm = SPAKE2Plus::Algorithms.new(Curve::P256, OpenSSL::Algorithm::SHA256, MAC::CMAC)

      prover = Protocol.new(
        algorithm: algorithm,
        context: context,
        random: x,
        w0: w0
      )

      verifier = Protocol.new(
        algorithm: algorithm,
        context: context,
        random: y,
        w0: w0
      )

      prover.compute_x.should eq share_p
      verifier.compute_y.should eq share_v

      h_ay = "d66386ee8033bf56387db3543691064e".hexbytes
      h_bx = "391070acb88ecc74dfe079cd0b8b52dc".hexbytes

      result = prover.compute_secret_and_verifiers_from_y(w1, share_p, share_v)
      result[0].should eq ke
      result[1].should eq h_ay
      result[2].should eq h_bx

      result = verifier.compute_secret_and_verifiers_from_x(l, share_p, share_v)
      result[0].should eq ke
      result[1].should eq h_ay
      result[2].should eq h_bx
    end

    it "works against SPAKE2+-P256-SHA256-HKDF draft-01 Test Vector 2" do
      context = "SPAKE2+-P256-SHA256-HKDF draft-01"
      id_prover = "client"
      id_verifier = "server"

      w0 = BigInt.new("e6887cf9bdfb7579c69bf47928a84514b5e355ac034863f7ffaf4390e67d798c", base: 16)
      w1 = BigInt.new("24b5ae4abda868ec9336ffc3b78ee31c5755bef1759227ef5372ca139b94e512", base: 16)
      l = "0495645cfb74df6e58f9748bb83a86620bab7c82e107f57d6870da8cbcb2ff9f7063a14b6402c62f99afcb9706a4d1a143273259fe76f1c605a3639745a92154b9".hexbytes
      x = BigInt.new("8b0f3f383905cf3a3bb955ef8fb62e24849dd349a05ca79aafb18041d30cbdb6", base: 16)
      y = BigInt.new("2e0895b0e763d6d5a9564433e64ac3cac74ff897f6c3445247ba1bab40082a91", base: 16)
      share_p = "04af09987a593d3bac8694b123839422c3cc87e37d6b41c1d630f000dd64980e537ae704bcede04ea3bec9b7475b32fa2ca3b684be14d11645e38ea6609eb39e7e".hexbytes
      share_v = "04417592620aebf9fd203616bbb9f121b730c258b286f890c5f19fea833a9c900cbe9057bc549a3e19975be9927f0e7614f08d1f0a108eede5fd7eb5624584a4f4".hexbytes

      ke = "801db297654816eb4f02868129b9dc89".hexbytes
      h_ay = "d4376f2da9c72226dd151b77c2919071155fc22a2068d90b5faa6c78c11e77dd".hexbytes
      h_bx = "0660a680663e8c5695956fb22dff298b1d07a526cf3cc591adfecd1f6ef6e02e".hexbytes

      algorithm = SPAKE2Plus::Algorithms.new(Curve::P256, OpenSSL::Algorithm::SHA256, MAC::HMAC)

      prover = Protocol.new(
        algorithm: algorithm,
        context: context,
        random: x,
        w0: w0,
        id_prover: id_prover,
        id_verifier: id_verifier
      )

      verifier = Protocol.new(
        algorithm: algorithm,
        context: context,
        random: y,
        w0: w0,
        id_prover: id_prover,
        id_verifier: id_verifier
      )

      prover.compute_x.should eq share_p
      verifier.compute_y.should eq share_v

      result = prover.compute_secret_and_verifiers_from_y(w1, share_p, share_v)
      result[0].should eq ke
      result[1].should eq h_ay
      result[2].should eq h_bx

      result = verifier.compute_secret_and_verifiers_from_x(l, share_p, share_v)
      result[0].should eq ke
      result[1].should eq h_ay
      result[2].should eq h_bx

      algorithm = SPAKE2Plus::Algorithms.new(Curve::P256, OpenSSL::Algorithm::SHA256, MAC::CMAC)

      prover = Protocol.new(
        algorithm: algorithm,
        context: context,
        random: x,
        w0: w0,
        id_prover: id_prover,
        id_verifier: id_verifier
      )

      verifier = Protocol.new(
        algorithm: algorithm,
        context: context,
        random: y,
        w0: w0,
        id_prover: id_prover,
        id_verifier: id_verifier
      )

      prover.compute_x.should eq share_p
      verifier.compute_y.should eq share_v

      h_ay = "ad04419077d806572fd7c8ab6d78656a".hexbytes
      h_bx = "aa076038a84938018a276e673ee7583e".hexbytes

      result = prover.compute_secret_and_verifiers_from_y(w1, share_p, share_v)
      result[0].should eq ke
      result[1].should eq h_ay
      result[2].should eq h_bx

      result = verifier.compute_secret_and_verifiers_from_x(l, share_p, share_v)
      result[0].should eq ke
      result[1].should eq h_ay
      result[2].should eq h_bx
    end

    it "works against SPAKE2+-P256-SHA256-HKDF draft-01 Test Vector 3" do
      context = "SPAKE2+-P256-SHA256-HKDF draft-01"
      id_prover = ""
      id_verifier = "server"

      w0 = BigInt.new("e6887cf9bdfb7579c69bf47928a84514b5e355ac034863f7ffaf4390e67d798c", base: 16)
      w1 = BigInt.new("24b5ae4abda868ec9336ffc3b78ee31c5755bef1759227ef5372ca139b94e512", base: 16)
      l = "0495645cfb74df6e58f9748bb83a86620bab7c82e107f57d6870da8cbcb2ff9f7063a14b6402c62f99afcb9706a4d1a143273259fe76f1c605a3639745a92154b9".hexbytes
      x = BigInt.new("ba0f0f5b78ef23fd07868e46aeca63b51fda519a3420501acbe23d53c2918748", base: 16)
      y = BigInt.new("39397fbe6db47e9fbd1a263d79f5d0aaa44df26ce755f78e092644b434533a42", base: 16)
      share_p = "04c14d28f4370fea20745106cea58bcfb60f2949fa4e131b9aff5ea13fd5aa79d507ae1d229e447e000f15eb78a9a32c2b88652e3411642043c1b2b7992cf2d4de".hexbytes
      share_v = "04d1bee3120fd87e86fe189cb952dc688823080e62524dd2c08dffe3d22a0a8986aa64c9fe0191033cafbc9bcaefc8e2ba8ba860cd127af9efdd7f1c3a41920fe8".hexbytes

      ke = "2ea40e4badfa5452b5744dc5983e99ba".hexbytes
      h_ay = "e564c93b3015efb946dc16d642bbe7d1c8da5be164ed9fc3bae4e0ff86e1bd3c".hexbytes
      h_bx = "072a94d9a54edc201d8891534c2317cadf3ea3792827f479e873f93e90f21552".hexbytes

      algorithm = SPAKE2Plus::Algorithms.new(Curve::P256, OpenSSL::Algorithm::SHA256, MAC::HMAC)

      prover = Protocol.new(
        algorithm: algorithm,
        context: context,
        random: x,
        w0: w0,
        id_prover: id_prover,
        id_verifier: id_verifier
      )

      verifier = Protocol.new(
        algorithm: algorithm,
        context: context,
        random: y,
        w0: w0,
        id_prover: id_prover,
        id_verifier: id_verifier
      )

      prover.compute_x.should eq share_p
      verifier.compute_y.should eq share_v

      result = prover.compute_secret_and_verifiers_from_y(w1, share_p, share_v)
      result[0].should eq ke
      result[1].should eq h_ay
      result[2].should eq h_bx

      result = verifier.compute_secret_and_verifiers_from_x(l, share_p, share_v)
      result[0].should eq ke
      result[1].should eq h_ay
      result[2].should eq h_bx

      algorithm = SPAKE2Plus::Algorithms.new(Curve::P256, OpenSSL::Algorithm::SHA256, MAC::CMAC)

      prover = Protocol.new(
        algorithm: algorithm,
        context: context,
        random: x,
        w0: w0,
        id_prover: id_prover,
        id_verifier: id_verifier
      )

      verifier = Protocol.new(
        algorithm: algorithm,
        context: context,
        random: y,
        w0: w0,
        id_prover: id_prover,
        id_verifier: id_verifier
      )

      prover.compute_x.should eq share_p
      verifier.compute_y.should eq share_v

      h_ay = "94aacd28128dc2ce1d7f5684119d553c".hexbytes
      h_bx = "bc6615eb68af10d329b2acb2d4545d97".hexbytes

      result = prover.compute_secret_and_verifiers_from_y(w1, share_p, share_v)
      result[0].should eq ke
      result[1].should eq h_ay
      result[2].should eq h_bx

      result = verifier.compute_secret_and_verifiers_from_x(l, share_p, share_v)
      result[0].should eq ke
      result[1].should eq h_ay
      result[2].should eq h_bx
    end

    it "works with Matter pin codes" do
      # the configuration matter uses
      algorithm = SPAKE2Plus::Algorithms.new(:p256, :sha256, :hmac)

      # As part of registration we swap salt and iteration params
      # PBKDF Param Request
      iterations = Random.new.rand(1000..100_000)
      salt = Random.new.random_bytes(Random.new.rand(16..32))

      # both initiator and responder encode the password / pin
      # for Matter this is a UInt32 passcode encoded in little endian
      passcode = 1122334455_u32
      io = IO::Memory.new
      io.write_bytes(passcode, IO::ByteFormat::LittleEndian)
      context = io.to_slice

      # > The Initiator provides PAKE Contribution
      # ==========================================
      w0, w1 = algorithm.compute_w0_w1(context, salt, iterations)
      initiator = SPAKE2Plus.new(context, w0, algorithm)
      x = initiator.compute_x # send x as pake1 to responder

      # < Responder provides PAKE Contribution and verification
      # =======================================================
      w0, l = algorithm.compute_w0_l(context, salt, iterations)
      responder = SPAKE2Plus.new(context, w0, algorithm)
      y = responder.compute_y
      _ke, h_ay, resp_verify = responder.compute_secret_and_verifiers_from_x(l, x, y)
      # send y, resp_verify as pake2 to initiator

      # > The Initiator verifies and sends verifier
      # ===========================================
      _ke, init_verify, h_bx = initiator.compute_secret_and_verifiers_from_y(w1, x, y)
      raise "init verification failed" unless h_bx == resp_verify
      # send init_verify as pake3 to responder

      # < Responder validates and sends PakeFinished
      # ============================================
      raise "resp verification failed" unless h_ay == init_verify
    end
  end
end
