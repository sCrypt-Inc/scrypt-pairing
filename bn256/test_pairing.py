import os
import json
import random

from scryptlib import (
        compile_contract, build_contract_class, build_type_classes
        )


if __name__ == '__main__':
    contract = 'testPairing.scrypt' 

    compiler_result = compile_contract(contract, debug=False)
    desc = compiler_result.to_desc()

    # Load desc instead:
    #with open('./out/testCurve_desc.json', 'r') as f:
    #    desc = json.load(f)

    type_classes = build_type_classes(desc)

    BN256PairingTest = build_contract_class(desc)
    bn256_pairing_test = BN256PairingTest()

    #assert bn256_pairing_test.testMiller(

    #).verify()

