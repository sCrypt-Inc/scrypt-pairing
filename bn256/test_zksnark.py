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

    # Also test optimized version with precalculated vk.alpha * vk.beta. # TODO: change millera1b1 vals
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
            
