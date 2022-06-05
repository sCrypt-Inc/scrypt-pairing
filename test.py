import os
import json
import random

from scryptlib import (
        compile_contract, build_contract_class, build_type_classes, Sig
        )

# We use mister Buterins BN128 imlementation: https://github.com/ethereum/py_pairing
from py_ecc import bn128


p = 21888242871839275222246405745257275088696311157297823662689037894645226208583

if __name__ == '__main__':
    contract = 'testCurve.scrypt' 

    compiler_result = compile_contract(contract, debug=True)
    desc = compiler_result.to_desc()

    # Load desc instead:
    #with open('./out/testCurve_desc.json', 'r') as f:
    #    desc = json.load(f)

    type_classes = build_type_classes(desc)
    PointFQ = type_classes['PointFQ']

    BN128CurveTest = build_contract_class(desc)
    bn128_curve_test = BN128CurveTest()


    ###### FQ #######

    key_priv = random.randint(0, p)
    #key_priv = 10217434817925140929608337607270499770332676702964002029488453146631842237125
    key_pub = bn128.multiply(bn128.G1, key_priv)

    # Point addition
    to_add = random.randint(0, p)
    point_to_add = bn128.multiply(bn128.G1, to_add)
    point_sum = bn128.add(key_pub, point_to_add)

    # Point doubling
    point_doubled = bn128.double(key_pub)

    # Scalar multiplication
    scalar = random.randint(0, p)
    point_scaled = bn128.multiply(key_pub, scalar)

    assert bn128_curve_test.testAddFQ(
                PointFQ({ 'x': key_pub[0].n, 'y': key_pub[1].n}), 
                PointFQ({ 'x': point_to_add[0].n, 'y': point_to_add[1].n}), 
                PointFQ({ 'x': point_sum[0].n, 'y': point_sum[1].n}), 
            ).verify()

    assert bn128_curve_test.testDoubleFQ(
                PointFQ({ 'x': key_pub[0].n, 'y': key_pub[1].n}), 
                PointFQ({ 'x': point_doubled[0].n, 'y': point_doubled[1].n}), 
            ).verify()

    assert bn128_curve_test.testMultPointByScalarFQ(
                PointFQ({ 'x': key_pub[0].n, 'y': key_pub[1].n}), 
                scalar, 
                PointFQ({ 'x': point_scaled[0].n, 'y': point_scaled[1].n}), 
            ).verify()


    ###### FQ2 #######

    PointFQ2 = type_classes['PointFQ2']

    key_priv = random.randint(0, p)
    #key_priv = 10217434817925140929608337607270499770332676702964002029488453146631842237125
    key_pub = bn128.multiply(bn128.G2, key_priv)

    # Polynomial inversion
    inv_res = key_pub[0].inv()

    # Point addition
    to_add = random.randint(0, p)
    point_to_add = bn128.multiply(bn128.G2, to_add)
    point_sum = bn128.add(key_pub, point_to_add)

    # Point doubling
    point_doubled = bn128.double(key_pub)

    # Scalar multiplication
    scalar = random.randint(0, p)
    point_scaled = bn128.multiply(key_pub, scalar)


    assert bn128_curve_test.testFQ2modInv(
            [key_pub[0].coeffs[0].n, key_pub[0].coeffs[1].n], 
            [inv_res.coeffs[0].n, inv_res.coeffs[1].n]
            ).verify()

    assert bn128_curve_test.testAddFQ2(
            PointFQ2({ 
                'x': [key_pub[0].coeffs[0].n, key_pub[0].coeffs[1].n],
                'y': [key_pub[1].coeffs[0].n, key_pub[1].coeffs[1].n]
                }),
            PointFQ2({ 
                'x': [point_to_add[0].coeffs[0].n, point_to_add[0].coeffs[1].n],
                'y': [point_to_add[1].coeffs[0].n, point_to_add[1].coeffs[1].n]
                }),
            PointFQ2({ 
                'x': [point_sum[0].coeffs[0].n, point_sum[0].coeffs[1].n],
                'y': [point_sum[1].coeffs[0].n, point_sum[1].coeffs[1].n]
                })
            ).verify()

    assert bn128_curve_test.testDoubleFQ2(
            PointFQ2({ 
                'x': [key_pub[0].coeffs[0].n, key_pub[0].coeffs[1].n],
                'y': [key_pub[1].coeffs[0].n, key_pub[1].coeffs[1].n]
                }),
            PointFQ2({ 
                'x': [point_doubled[0].coeffs[0].n, point_doubled[0].coeffs[1].n],
                'y': [point_doubled[1].coeffs[0].n, point_doubled[1].coeffs[1].n]
                })
            ).verify()

    assert bn128_curve_test.testMultFQ2(
            PointFQ2({ 
                'x': [key_pub[0].coeffs[0].n, key_pub[0].coeffs[1].n],
                'y': [key_pub[1].coeffs[0].n, key_pub[1].coeffs[1].n]
                }),
            scalar,
            PointFQ2({ 
                'x': [point_scaled[0].coeffs[0].n, point_scaled[0].coeffs[1].n],
                'y': [point_scaled[1].coeffs[0].n, point_scaled[1].coeffs[1].n]
                })
            ).verify()
