import os
import json
import random

from scryptlib import (
        compile_contract, build_contract_class, build_type_classes
        )


contract = 'testZKSNARK.scrypt' 

compiler_result = compile_contract(contract, debug=True)
desc = compiler_result.to_desc()

## Load desc instead:
#with open('./out/testZKSNARK_desc.json', 'r') as f:
#    desc = json.load(f)

type_classes = build_type_classes(desc)
G2Point = type_classes['G2Point']
G1Point = type_classes['G1Point']
FQ2 = type_classes['FQ2']
FQ6 = type_classes['FQ6']
FQ12 = type_classes['FQ12']
Proof = type_classes['Proof']
VerifyingKey = type_classes['VerifyingKey']

ZKSNARKTest = build_contract_class(desc)
zksnark_test = ZKSNARKTest()


def test_verify_0():
    proof = Proof({
        'a': G1Point({
            'x': 0x11421cbecbed165d0e4ce5efe39df80203ac655625d25edfd74628381e4ac8cf,
            'y': 0x1dfac3ecc3e619af99984ddf836d444bf8bd0fcf49f05065587cf5e72be61c94
            }),
        'b': G2Point({
                'x': FQ2({
                    'x': 0x2411ea2a3a6df04fb16a69a8fa63abb84cf0dc180a38e9251981a766fe255859,
                    'y': 0x11792272e45f6f84d2fb6f5c49cf87895fd22f22131b3d67e0930f6246f34141,
                    }),
                'y': FQ2({
                    'x': 0x1742c7762a4b1c2d34e0e78078e57537093f2a19959b1adaa6788d488ed919cf,
                    'y': 0x26b44df40b909932ba8a12df0bc36f778cbd71b1cf96c5eed317c6ea10ea67b6,
                    })
             }),
        'c': G1Point({
            'x': 0x2599b516fe83a2e3e7a48a6a19556865dd231d028dfdc804bf45ebe659440b00,
            'y': 0x2378c4b624fd1a290488683c8d592648ad3e23686f73667e40e9e697a4263927
            })
    })

    vk = VerifyingKey({
        'alpha': G1Point({
            'x': 0x1431ad41f72571346c81f248fb86519f434e9d1c775654dd1375c0084137349c,
            'y': 0x04b49904e75d7cb0573d0965258f07498f2235e43e4565b7799837128d6c2471
            }),
        'beta': G2Point({
                'x': FQ2({
                    'x': 0x2a181ee7fcc6cf49dcbd6fe79bda0b5878d06faeeb0c1294ad767b58ab6dfcc3,
                    'y': 0x230a251c98347bc4b02d22b27fba724483157ab7dfa1059b43adcecaf986a468,
                    }),
                'y': FQ2({
                    'x': 0x06c763425dee53dc5b663e763517c75fc7f872f6f9ea0196e80ca56e0cf93c3f,
                    'y': 0x117c1209e00335e68ef48dd8c8e8c2cbef4d55371d5fe3f04b10776482ea03ca,
                    })
             }),
        'gamma': G2Point({
                'x': FQ2({
                    'x': 0x1d7b5c4e68679bde000cbb8aaab84470937e154551c3d1e983b3c8811d2a3aa9,
                    'y': 0x0b8c2adad07f1d83427c80e5bab2a69dc128a18db78f386d822c0b2a33e153e7,
                    }),
                'y': FQ2({
                    'x': 0x2d88aac9fb2fc1e681b164c8554ad46f2a7cd2716dbd4c447992065c2623cb46,
                    'y': 0x2d05db174803826dc866151d766a36f4ba885fb9ce5b6352d739efac39ce3215,
                    })
             }),
        'delta': G2Point({
                'x': FQ2({
                    'x': 0x157ea19da719966603e5aa6a1964e8616889bee845e7c421650236725ea59770,
                    'y': 0x237ea049a5a7e95e92303b7066e5e09c2213e20665f30613202d7cb4bba35657,
                    }),
                'y': FQ2({
                    'x': 0x0cc85f10483a01b9a134027551eb8fb6041eb7a3d4872eca39ebdb606d2295a6,
                    'y': 0x2385eecc94831cbd97a7683a8d53fb8639b9ac7d192da7b3e402afc34ca2ae16,
                    })
             }),
        'gamma_abc': [
            G1Point({
                'x': 0x032c138a2e2219febe77fe29ce8c928fcefcf0ef3d0bd0c3b928ac9cfeed5cde,
                'y': 0x1a223d92d6fa5296b6ab769c0f4bcba03bbe4915e5296b241e16f5e970e05016
            }),
            G1Point({
                'x': 0x077dcfe522a9a7b6ff52a7ab4c989d99ba4cb13ab997f3b036a92a806098ac14,
                'y': 0x046dacd8734031da8abf6aa2c1fc977442ed6023ad138a08265e8f28fd66b972
            })
        ]
    })

    inputs = [0x000000000000000000000000000000000000000000000000000000000001bba1]

    assert zksnark_test.testVerify(
        inputs,
        proof,
        vk
    ).verify()        

    # Also test optimized version with precalculated vk.alpha * vk.beta.
    millera1b1 = FQ12({
        'x': FQ6({
            'x': FQ2({
                'x': 2127356783905559593272756835978861745876488732674186717002137844997639056324,
                'y': -25399583956667205141837684477276819181966124473649400873238383836865208168593
                }),
            'y': FQ2({
                'x': -16711428091461918511096809274034428548482845969609499954997089082175334525717,
                'y': -12211292625401886850243523359594870225579183334795450974496925675022465811288
                }),
            'z': FQ2({
                'x': -64589125938171024488928895725585582843215161613769324288899182089035139680481,
                'y': 100585451108012376489520314045669715950877884161284756461348374288652621138550
                })
            }),
        'y': FQ6({
            'x': FQ2({
                'x': 17128697032009708071441534394297333564991166476249799533395840138644743465049,
                'y': 2016396721973396327764393052769706730962680626481266267397819585211285681784
                }),
            'y': FQ2({
                'x': -15543929344890631450579637055954481150167653191503975534944704416060157555582,
                'y': -86216297469984927837207428415834555765584774641150438316220469703187627590807
                }),
            'z': FQ2({
                'x': 174445358656777515364411221148061800312292041223077934483774996724048396434783,
                'y': 225468647982510873424836217733874917878784354743069798294557806978737945535998
                })
            })
        })

    assert zksnark_test.testVerifyOptimized(
        inputs,
        proof,
        vk,
        millera1b1
    ).verify()        
            

# Testi with 5 public inputs. Requires change of N constant.
#def test_verify_1():
#    proof = Proof({
#        'a': G1Point({
#            'x': 0x2cd28f7e33cad0b4732ce6e26b3cf6c2dc3fa30bfa852cf4b586937a6ec51d13,
#            'y': 0x2e5847f9f341151bed6b6c2de73f554d2e734e301f7e1e396e2623f395f75afc
#            }),
#        'b': G2Point({
#                'x': FQ2({
#                    'x': 0x037e54b9e256f3589540cd64e3bcbe855ad0badfeb51772b81a992bccd34eba9,
#                    'y': 0x278f2d720fe90ca180f2796177bd4a90a9d698b21afab3483283f4e5d76c58bf,
#                    }),
#                'y': FQ2({
#                    'x': 0x12bcb8c0eaac13ef344053977c6455b5518b61a0c1d078cb9bec8084a93e6dfd,
#                    'y': 0x0724f53fb932fd88c01ae8c36cb7b959bffe28e9541c69d585799a5e82d791e7,
#                    })
#             }),
#        'c': G1Point({
#            'x': 0x00f934d287b223ffd205b6adfc0639b2280426108a2c5c048651cddb0d08746c,
#            'y': 0x0f41e421c27aa85cf560839d03507a6f6b466d5c82ba1b14469f24acb9f16c8b
#            })
#    })
#
#    vk = VerifyingKey({
#        'alpha': G1Point({
#            'x': 0x21b0d8351269e5ea12146142f6558b94c19d79e91c17aab7c5c9ce54288a4e7d,
#            'y': 0x2406404e3866cd186d27a48df6819f26c7cbf3025c0a3f5d6e5460ed542c2bf1
#            }),
#        'beta': G2Point({
#                'x': FQ2({
#                    'x': 0x2f393f33a801a29f68a35d823bc231100de216100e9031002f3a7d0bd35365b1,
#                    'y': 0x230a787ae20988519aa4e8721b61b9369f0a26f76cb942cdfb72493f001b94cf,
#                    }),
#                'y': FQ2({
#                    'x': 0x0f712e8fff65977d7c1eb398c7473051cf645e9cd087eb1b4865cf69cd2bcdb3,
#                    'y': 0x09b356ac11216a3bcab42d5a9b451cf3d571f6699c0156ce8044e328fe1ff8b4,
#                    })
#             }),
#        'gamma': G2Point({
#                'x': FQ2({
#                    'x': 0x2cbc13134030196435d750cbfd69f967f949f0d7dc78d82fd246f67a476a4d09,
#                    'y': 0x0aca874766a4b276dac9a0c7e8383ef0c574ec3b9d1f4d0fbc8bf228345cce9c,
#                    }),
#                'y': FQ2({
#                    'x': 0x0cc37dc9c60a4cd9f6fe4c571d3ee7f4129f54a8862a933cdcd8d917422c3621,
#                    'y': 0x2d81f43fde136da5c72660b9149c5bff08057cac5056a33a696df849ea9ffb29,
#                    })
#             }),
#        'delta': G2Point({
#                'x': FQ2({
#                    'x': 0x115ce77b63488bb23cd41ad0852a6af72bc128fe8fd01c1da57889db9fd1a9a6,
#                    'y': 0x09fd82910143e0af49b0b4ac1c36bbd58309ef5c8b6ab761d55870e9264a9f9b,
#                    }),
#                'y': FQ2({
#                    'x': 0x23cba54537e584bb472dc50d4d9a94da5d534b06a93a9149baeb6120bfa6e18a,
#                    'y': 0x0cbfd2646fc48d763b19ca02fd4144b6feedf9d8c015f6a3e78cec7f404379c5,
#                    })
#             }),
#        'gamma_abc': [
#            G1Point({
#                'x': 0x178baac7a43f2528b250f7e809d3fb261e8e67ca0342060dd62cba8d3d839073,
#                'y': 0x1c914b1f67466782ef8a301a4a187121df366f091702278aa9bbfc5153cdbff9
#            }),
#            G1Point({
#                'x': 0x0df23bc1a5c855a97d4c48092d63eb1f157b0e728becf4c3cce9dbe7da7efd05,
#                'y': 0x269c824014476cc4d04a48e501efa96c35dc1824433a9ba512b4ae397f9b9567
#            }),
#            G1Point({
#                'x': 0x076110a416a7034a85091bc87fab9bef7a42cdcc250a853c2ea6b5ceb0943eab,
#                'y': 0x022c9681d5bcb6a8c40403bc2e6996838aee2e25b83c0fc314fab969314c0734
#            }),
#            G1Point({
#                'x': 0x1b91debaddd8eeb8b1aa5038169dbdc4bc8be9aeeae248bb14f58fcc10456fd9,
#                'y': 0x07983a7381aa9ec3afe42dfa9a2720d843b14b0502004e67c0d3d3e827bfe459
#            }),
#            G1Point({
#                'x': 0x170d92322201e5b7b5ff86a89c1d3a746ce868e9b87399612c4ac6b953234f50,
#                'y': 0x00408cf29c8412f19a6c6144fca3ae8eb47c18771640daadd406b66e0074b946
#            }),
#            G1Point({
#                'x': 0x2592fd12b404668a1aac6a48ae8c9db944f7d6ecf5375969210beff97d459100,
#                'y': 0x22f745fdbb492d90cecaab3374365d2570f684becee29eaabc25f8836c8de417
#            })
#        ]
#    })
#
#    inputs = [
#        0x00000000000000000000000000000000c31b30bf30a687cf96edaf12d74129ca,
#        0x0000000000000000000000000000000021bd667bf2cf7723131c9fe26b9310c9,
#        0x0000000000000000000000000000000000000000000000000000000000000000,
#        0x0000000000000000000000000000000000000000000000000000000000000000,
#        0x0000000000000000000000000000000000000000000000000000000000000000
#    ]
#
#    assert zksnark_test.testVerify(
#        inputs,
#        proof,
#        vk
#    ).verify()        
