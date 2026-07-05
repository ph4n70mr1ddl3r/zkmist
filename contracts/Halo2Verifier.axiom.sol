
// SPDX-License-Identifier: MIT

pragma solidity 0.8.19;

contract Halo2Verifier {
    fallback(bytes calldata) external returns (bytes memory) {
        assembly ("memory-safe") {
            // Enforce that Solidity memory layout is respected
            let data := mload(0x40)
            if iszero(eq(data, 0x80)) {
                revert(0, 0)
            }

            let success := true
            let f_p := 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47
            let f_q := 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001
            function validate_ec_point(x, y) -> valid {
                {
                    let x_lt_p := lt(x, 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47)
                    let y_lt_p := lt(y, 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47)
                    valid := and(x_lt_p, y_lt_p)
                }
                {
                    let y_square := mulmod(y, y, 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47)
                    let x_square := mulmod(x, x, 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47)
                    let x_cube := mulmod(x_square, x, 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47)
                    let x_cube_plus_3 := addmod(x_cube, 3, 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47)
                    let is_affine := eq(x_cube_plus_3, y_square)
                    valid := and(valid, is_affine)
                }
            }
            mstore(0xa0, mod(calldataload(0x0), f_q))
mstore(0xc0, mod(calldataload(0x20), f_q))
mstore(0xe0, mod(calldataload(0x40), f_q))
mstore(0x80, 10693693449904129751092444824539694746290208948937306215663664286703619439984)

        {
            let x := calldataload(0x60)
            mstore(0x100, x)
            let y := calldataload(0x80)
            mstore(0x120, y)
            success := and(validate_ec_point(x, y), success)
        }
mstore(0x140, keccak256(0x80, 192))
{
            let hash := mload(0x140)
            mstore(0x160, mod(hash, f_q))
            mstore(0x180, hash)
        }

        {
            let x := calldataload(0xa0)
            mstore(0x1a0, x)
            let y := calldataload(0xc0)
            mstore(0x1c0, y)
            success := and(validate_ec_point(x, y), success)
        }

        {
            let x := calldataload(0xe0)
            mstore(0x1e0, x)
            let y := calldataload(0x100)
            mstore(0x200, y)
            success := and(validate_ec_point(x, y), success)
        }
mstore(0x220, keccak256(0x180, 160))
{
            let hash := mload(0x220)
            mstore(0x240, mod(hash, f_q))
            mstore(0x260, hash)
        }
mstore8(640, 1)
mstore(0x280, keccak256(0x260, 33))
{
            let hash := mload(0x280)
            mstore(0x2a0, mod(hash, f_q))
            mstore(0x2c0, hash)
        }

        {
            let x := calldataload(0x120)
            mstore(0x2e0, x)
            let y := calldataload(0x140)
            mstore(0x300, y)
            success := and(validate_ec_point(x, y), success)
        }

        {
            let x := calldataload(0x160)
            mstore(0x320, x)
            let y := calldataload(0x180)
            mstore(0x340, y)
            success := and(validate_ec_point(x, y), success)
        }

        {
            let x := calldataload(0x1a0)
            mstore(0x360, x)
            let y := calldataload(0x1c0)
            mstore(0x380, y)
            success := and(validate_ec_point(x, y), success)
        }
mstore(0x3a0, keccak256(0x2c0, 224))
{
            let hash := mload(0x3a0)
            mstore(0x3c0, mod(hash, f_q))
            mstore(0x3e0, hash)
        }

        {
            let x := calldataload(0x1e0)
            mstore(0x400, x)
            let y := calldataload(0x200)
            mstore(0x420, y)
            success := and(validate_ec_point(x, y), success)
        }

        {
            let x := calldataload(0x220)
            mstore(0x440, x)
            let y := calldataload(0x240)
            mstore(0x460, y)
            success := and(validate_ec_point(x, y), success)
        }

        {
            let x := calldataload(0x260)
            mstore(0x480, x)
            let y := calldataload(0x280)
            mstore(0x4a0, y)
            success := and(validate_ec_point(x, y), success)
        }

        {
            let x := calldataload(0x2a0)
            mstore(0x4c0, x)
            let y := calldataload(0x2c0)
            mstore(0x4e0, y)
            success := and(validate_ec_point(x, y), success)
        }
mstore(0x500, keccak256(0x3e0, 288))
{
            let hash := mload(0x500)
            mstore(0x520, mod(hash, f_q))
            mstore(0x540, hash)
        }
mstore(0x560, mod(calldataload(0x2e0), f_q))
mstore(0x580, mod(calldataload(0x300), f_q))
mstore(0x5a0, mod(calldataload(0x320), f_q))
mstore(0x5c0, mod(calldataload(0x340), f_q))
mstore(0x5e0, mod(calldataload(0x360), f_q))
mstore(0x600, mod(calldataload(0x380), f_q))
mstore(0x620, mod(calldataload(0x3a0), f_q))
mstore(0x640, mod(calldataload(0x3c0), f_q))
mstore(0x660, mod(calldataload(0x3e0), f_q))
mstore(0x680, mod(calldataload(0x400), f_q))
mstore(0x6a0, mod(calldataload(0x420), f_q))
mstore(0x6c0, mod(calldataload(0x440), f_q))
mstore(0x6e0, mod(calldataload(0x460), f_q))
mstore(0x700, mod(calldataload(0x480), f_q))
mstore(0x720, mod(calldataload(0x4a0), f_q))
mstore(0x740, mod(calldataload(0x4c0), f_q))
mstore(0x760, mod(calldataload(0x4e0), f_q))
mstore(0x780, mod(calldataload(0x500), f_q))
mstore(0x7a0, mod(calldataload(0x520), f_q))
mstore(0x7c0, keccak256(0x540, 640))
{
            let hash := mload(0x7c0)
            mstore(0x7e0, mod(hash, f_q))
            mstore(0x800, hash)
        }
mstore8(2080, 1)
mstore(0x820, keccak256(0x800, 33))
{
            let hash := mload(0x820)
            mstore(0x840, mod(hash, f_q))
            mstore(0x860, hash)
        }

        {
            let x := calldataload(0x540)
            mstore(0x880, x)
            let y := calldataload(0x560)
            mstore(0x8a0, y)
            success := and(validate_ec_point(x, y), success)
        }
mstore(0x8c0, keccak256(0x860, 96))
{
            let hash := mload(0x8c0)
            mstore(0x8e0, mod(hash, f_q))
            mstore(0x900, hash)
        }

        {
            let x := calldataload(0x580)
            mstore(0x920, x)
            let y := calldataload(0x5a0)
            mstore(0x940, y)
            success := and(validate_ec_point(x, y), success)
        }
mstore(0x960, mulmod(mload(0x520), mload(0x520), f_q))
mstore(0x980, mulmod(mload(0x960), mload(0x960), f_q))
mstore(0x9a0, mulmod(mload(0x980), mload(0x980), f_q))
mstore(0x9c0, mulmod(mload(0x9a0), mload(0x9a0), f_q))
mstore(0x9e0, mulmod(mload(0x9c0), mload(0x9c0), f_q))
mstore(0xa00, mulmod(mload(0x9e0), mload(0x9e0), f_q))
mstore(0xa20, mulmod(mload(0xa00), mload(0xa00), f_q))
mstore(0xa40, mulmod(mload(0xa20), mload(0xa20), f_q))
mstore(0xa60, mulmod(mload(0xa40), mload(0xa40), f_q))
mstore(0xa80, mulmod(mload(0xa60), mload(0xa60), f_q))
mstore(0xaa0, mulmod(mload(0xa80), mload(0xa80), f_q))
mstore(0xac0, mulmod(mload(0xaa0), mload(0xaa0), f_q))
mstore(0xae0, mulmod(mload(0xac0), mload(0xac0), f_q))
mstore(0xb00, mulmod(mload(0xae0), mload(0xae0), f_q))
mstore(0xb20, mulmod(mload(0xb00), mload(0xb00), f_q))
mstore(0xb40, mulmod(mload(0xb20), mload(0xb20), f_q))
mstore(0xb60, mulmod(mload(0xb40), mload(0xb40), f_q))
mstore(0xb80, mulmod(mload(0xb60), mload(0xb60), f_q))
mstore(0xba0, mulmod(mload(0xb80), mload(0xb80), f_q))
mstore(0xbc0, mulmod(mload(0xba0), mload(0xba0), f_q))
mstore(0xbe0, mulmod(mload(0xbc0), mload(0xbc0), f_q))
mstore(0xc00, addmod(mload(0xbe0), 21888242871839275222246405745257275088548364400416034343698204186575808495616, f_q))
mstore(0xc20, mulmod(mload(0xc00), 21888232434711746154598842647110004286396165347431605739555851272621938401409, f_q))
mstore(0xc40, mulmod(mload(0xc20), 20975929243409798062839949658616274858986091382510192949221301676705706354487, f_q))
mstore(0xc60, addmod(mload(0x520), 912313628429477159406456086641000229562273017905841394476902509870102141130, f_q))
mstore(0xc80, mulmod(mload(0xc20), 495188420091111145957709789221178673495499187437761988132837836548330853701, f_q))
mstore(0xca0, addmod(mload(0x520), 21393054451748164076288695956036096415052865212978272355565366350027477641916, f_q))
mstore(0xcc0, mulmod(mload(0xc20), 16064522944768515290584536219762686197737451920702130080538975732575755569557, f_q))
mstore(0xce0, addmod(mload(0x520), 5823719927070759931661869525494588890810912479713904263159228454000052926060, f_q))
mstore(0xd00, mulmod(mload(0xc20), 14686510910986211321976396297238126901237973400949744736326777596334651355305, f_q))
mstore(0xd20, addmod(mload(0x520), 7201731960853063900270009448019148187310390999466289607371426590241157140312, f_q))
mstore(0xd40, mulmod(mload(0xc20), 10939663269433627367777756708678102241564365262857670666700619874077960926249, f_q))
mstore(0xd60, addmod(mload(0x520), 10948579602405647854468649036579172846983999137558363676997584312497847569368, f_q))
mstore(0xd80, mulmod(mload(0xc20), 15402826414547299628414612080036060696555554914079673875872749760617770134879, f_q))
mstore(0xda0, addmod(mload(0x520), 6485416457291975593831793665221214391992809486336360467825454425958038360738, f_q))
mstore(0xdc0, mulmod(mload(0xc20), 2785514556381676080176937710880804108647911392478702105860685610379369825016, f_q))
mstore(0xde0, addmod(mload(0x520), 19102728315457599142069468034376470979900453007937332237837518576196438670601, f_q))
mstore(0xe00, mulmod(mload(0xc20), 1, f_q))
mstore(0xe20, addmod(mload(0x520), 21888242871839275222246405745257275088548364400416034343698204186575808495616, f_q))
mstore(0xe40, mulmod(mload(0xc20), 1426404432721484388505361748317961535523355871255605456897797744433766488507, f_q))
mstore(0xe60, addmod(mload(0x520), 20461838439117790833741043996939313553025008529160428886800406442142042007110, f_q))
mstore(0xe80, mulmod(mload(0xc20), 19032961837237948602743626455740240236231119053033140765040043513661803148152, f_q))
mstore(0xea0, addmod(mload(0x520), 2855281034601326619502779289517034852317245347382893578658160672914005347465, f_q))
{
            let prod := mload(0xc60)

                prod := mulmod(mload(0xca0), prod, f_q)
                mstore(0xec0, prod)
            
                prod := mulmod(mload(0xce0), prod, f_q)
                mstore(0xee0, prod)
            
                prod := mulmod(mload(0xd20), prod, f_q)
                mstore(0xf00, prod)
            
                prod := mulmod(mload(0xd60), prod, f_q)
                mstore(0xf20, prod)
            
                prod := mulmod(mload(0xda0), prod, f_q)
                mstore(0xf40, prod)
            
                prod := mulmod(mload(0xde0), prod, f_q)
                mstore(0xf60, prod)
            
                prod := mulmod(mload(0xe20), prod, f_q)
                mstore(0xf80, prod)
            
                prod := mulmod(mload(0xe60), prod, f_q)
                mstore(0xfa0, prod)
            
                prod := mulmod(mload(0xea0), prod, f_q)
                mstore(0xfc0, prod)
            
                prod := mulmod(mload(0xc00), prod, f_q)
                mstore(0xfe0, prod)
            
        }
mstore(0x1020, 32)
mstore(0x1040, 32)
mstore(0x1060, 32)
mstore(0x1080, mload(0xfe0))
mstore(0x10a0, 21888242871839275222246405745257275088548364400416034343698204186575808495615)
mstore(0x10c0, 21888242871839275222246405745257275088548364400416034343698204186575808495617)
success := and(eq(staticcall(gas(), 0x5, 0x1020, 0xc0, 0x1000, 0x20), 1), success)
{
            
            let inv := mload(0x1000)
            let v
        
                    v := mload(0xc00)
                    mstore(3072, mulmod(mload(0xfc0), inv, f_q))
                    inv := mulmod(v, inv, f_q)
                
                    v := mload(0xea0)
                    mstore(3744, mulmod(mload(0xfa0), inv, f_q))
                    inv := mulmod(v, inv, f_q)
                
                    v := mload(0xe60)
                    mstore(3680, mulmod(mload(0xf80), inv, f_q))
                    inv := mulmod(v, inv, f_q)
                
                    v := mload(0xe20)
                    mstore(3616, mulmod(mload(0xf60), inv, f_q))
                    inv := mulmod(v, inv, f_q)
                
                    v := mload(0xde0)
                    mstore(3552, mulmod(mload(0xf40), inv, f_q))
                    inv := mulmod(v, inv, f_q)
                
                    v := mload(0xda0)
                    mstore(3488, mulmod(mload(0xf20), inv, f_q))
                    inv := mulmod(v, inv, f_q)
                
                    v := mload(0xd60)
                    mstore(3424, mulmod(mload(0xf00), inv, f_q))
                    inv := mulmod(v, inv, f_q)
                
                    v := mload(0xd20)
                    mstore(3360, mulmod(mload(0xee0), inv, f_q))
                    inv := mulmod(v, inv, f_q)
                
                    v := mload(0xce0)
                    mstore(3296, mulmod(mload(0xec0), inv, f_q))
                    inv := mulmod(v, inv, f_q)
                
                    v := mload(0xca0)
                    mstore(3232, mulmod(mload(0xc60), inv, f_q))
                    inv := mulmod(v, inv, f_q)
                mstore(0xc60, inv)

        }
mstore(0x10e0, mulmod(mload(0xc40), mload(0xc60), f_q))
mstore(0x1100, mulmod(mload(0xc80), mload(0xca0), f_q))
mstore(0x1120, mulmod(mload(0xcc0), mload(0xce0), f_q))
mstore(0x1140, mulmod(mload(0xd00), mload(0xd20), f_q))
mstore(0x1160, mulmod(mload(0xd40), mload(0xd60), f_q))
mstore(0x1180, mulmod(mload(0xd80), mload(0xda0), f_q))
mstore(0x11a0, mulmod(mload(0xdc0), mload(0xde0), f_q))
mstore(0x11c0, mulmod(mload(0xe00), mload(0xe20), f_q))
mstore(0x11e0, mulmod(mload(0xe40), mload(0xe60), f_q))
mstore(0x1200, mulmod(mload(0xe80), mload(0xea0), f_q))
{
            let result := mulmod(mload(0x11c0), mload(0xa0), f_q)
result := addmod(mulmod(mload(0x11e0), mload(0xc0), f_q), result, f_q)
result := addmod(mulmod(mload(0x1200), mload(0xe0), f_q), result, f_q)
mstore(4640, result)
        }
mstore(0x1240, mulmod(mload(0x5a0), mload(0x580), f_q))
mstore(0x1260, addmod(mload(0x560), mload(0x1240), f_q))
mstore(0x1280, addmod(mload(0x1260), sub(f_q, mload(0x5c0)), f_q))
mstore(0x12a0, mulmod(mload(0x1280), mload(0x620), f_q))
mstore(0x12c0, mulmod(mload(0x3c0), mload(0x12a0), f_q))
mstore(0x12e0, addmod(1, sub(f_q, mload(0x6e0)), f_q))
mstore(0x1300, mulmod(mload(0x12e0), mload(0x11c0), f_q))
mstore(0x1320, addmod(mload(0x12c0), mload(0x1300), f_q))
mstore(0x1340, mulmod(mload(0x3c0), mload(0x1320), f_q))
mstore(0x1360, mulmod(mload(0x6e0), mload(0x6e0), f_q))
mstore(0x1380, addmod(mload(0x1360), sub(f_q, mload(0x6e0)), f_q))
mstore(0x13a0, mulmod(mload(0x1380), mload(0x10e0), f_q))
mstore(0x13c0, addmod(mload(0x1340), mload(0x13a0), f_q))
mstore(0x13e0, mulmod(mload(0x3c0), mload(0x13c0), f_q))
mstore(0x1400, addmod(1, sub(f_q, mload(0x10e0)), f_q))
mstore(0x1420, addmod(mload(0x1100), mload(0x1120), f_q))
mstore(0x1440, addmod(mload(0x1420), mload(0x1140), f_q))
mstore(0x1460, addmod(mload(0x1440), mload(0x1160), f_q))
mstore(0x1480, addmod(mload(0x1460), mload(0x1180), f_q))
mstore(0x14a0, addmod(mload(0x1480), mload(0x11a0), f_q))
mstore(0x14c0, addmod(mload(0x1400), sub(f_q, mload(0x14a0)), f_q))
mstore(0x14e0, mulmod(mload(0x680), mload(0x240), f_q))
mstore(0x1500, addmod(mload(0x5e0), mload(0x14e0), f_q))
mstore(0x1520, addmod(mload(0x1500), mload(0x2a0), f_q))
mstore(0x1540, mulmod(mload(0x6a0), mload(0x240), f_q))
mstore(0x1560, addmod(mload(0x560), mload(0x1540), f_q))
mstore(0x1580, addmod(mload(0x1560), mload(0x2a0), f_q))
mstore(0x15a0, mulmod(mload(0x1580), mload(0x1520), f_q))
mstore(0x15c0, mulmod(mload(0x6c0), mload(0x240), f_q))
mstore(0x15e0, addmod(mload(0x1220), mload(0x15c0), f_q))
mstore(0x1600, addmod(mload(0x15e0), mload(0x2a0), f_q))
mstore(0x1620, mulmod(mload(0x1600), mload(0x15a0), f_q))
mstore(0x1640, mulmod(mload(0x1620), mload(0x700), f_q))
mstore(0x1660, mulmod(1, mload(0x240), f_q))
mstore(0x1680, mulmod(mload(0x520), mload(0x1660), f_q))
mstore(0x16a0, addmod(mload(0x5e0), mload(0x1680), f_q))
mstore(0x16c0, addmod(mload(0x16a0), mload(0x2a0), f_q))
mstore(0x16e0, mulmod(4131629893567559867359510883348571134090853742863529169391034518566172092834, mload(0x240), f_q))
mstore(0x1700, mulmod(mload(0x520), mload(0x16e0), f_q))
mstore(0x1720, addmod(mload(0x560), mload(0x1700), f_q))
mstore(0x1740, addmod(mload(0x1720), mload(0x2a0), f_q))
mstore(0x1760, mulmod(mload(0x1740), mload(0x16c0), f_q))
mstore(0x1780, mulmod(8910878055287538404433155982483128285667088683464058436815641868457422632747, mload(0x240), f_q))
mstore(0x17a0, mulmod(mload(0x520), mload(0x1780), f_q))
mstore(0x17c0, addmod(mload(0x1220), mload(0x17a0), f_q))
mstore(0x17e0, addmod(mload(0x17c0), mload(0x2a0), f_q))
mstore(0x1800, mulmod(mload(0x17e0), mload(0x1760), f_q))
mstore(0x1820, mulmod(mload(0x1800), mload(0x6e0), f_q))
mstore(0x1840, addmod(mload(0x1640), sub(f_q, mload(0x1820)), f_q))
mstore(0x1860, mulmod(mload(0x1840), mload(0x14c0), f_q))
mstore(0x1880, addmod(mload(0x13e0), mload(0x1860), f_q))
mstore(0x18a0, mulmod(mload(0x3c0), mload(0x1880), f_q))
mstore(0x18c0, addmod(1, sub(f_q, mload(0x720)), f_q))
mstore(0x18e0, mulmod(mload(0x18c0), mload(0x11c0), f_q))
mstore(0x1900, addmod(mload(0x18a0), mload(0x18e0), f_q))
mstore(0x1920, mulmod(mload(0x3c0), mload(0x1900), f_q))
mstore(0x1940, mulmod(mload(0x720), mload(0x720), f_q))
mstore(0x1960, addmod(mload(0x1940), sub(f_q, mload(0x720)), f_q))
mstore(0x1980, mulmod(mload(0x1960), mload(0x10e0), f_q))
mstore(0x19a0, addmod(mload(0x1920), mload(0x1980), f_q))
mstore(0x19c0, mulmod(mload(0x3c0), mload(0x19a0), f_q))
mstore(0x19e0, addmod(mload(0x760), mload(0x240), f_q))
mstore(0x1a00, mulmod(mload(0x19e0), mload(0x740), f_q))
mstore(0x1a20, addmod(mload(0x7a0), mload(0x2a0), f_q))
mstore(0x1a40, mulmod(mload(0x1a20), mload(0x1a00), f_q))
mstore(0x1a60, mulmod(mload(0x560), mload(0x640), f_q))
mstore(0x1a80, addmod(mload(0x1a60), mload(0x240), f_q))
mstore(0x1aa0, mulmod(mload(0x1a80), mload(0x720), f_q))
mstore(0x1ac0, addmod(mload(0x600), mload(0x2a0), f_q))
mstore(0x1ae0, mulmod(mload(0x1ac0), mload(0x1aa0), f_q))
mstore(0x1b00, addmod(mload(0x1a40), sub(f_q, mload(0x1ae0)), f_q))
mstore(0x1b20, mulmod(mload(0x1b00), mload(0x14c0), f_q))
mstore(0x1b40, addmod(mload(0x19c0), mload(0x1b20), f_q))
mstore(0x1b60, mulmod(mload(0x3c0), mload(0x1b40), f_q))
mstore(0x1b80, addmod(mload(0x760), sub(f_q, mload(0x7a0)), f_q))
mstore(0x1ba0, mulmod(mload(0x1b80), mload(0x11c0), f_q))
mstore(0x1bc0, addmod(mload(0x1b60), mload(0x1ba0), f_q))
mstore(0x1be0, mulmod(mload(0x3c0), mload(0x1bc0), f_q))
mstore(0x1c00, mulmod(mload(0x1b80), mload(0x14c0), f_q))
mstore(0x1c20, addmod(mload(0x760), sub(f_q, mload(0x780)), f_q))
mstore(0x1c40, mulmod(mload(0x1c20), mload(0x1c00), f_q))
mstore(0x1c60, addmod(mload(0x1be0), mload(0x1c40), f_q))
mstore(0x1c80, mulmod(mload(0xbe0), mload(0xbe0), f_q))
mstore(0x1ca0, mulmod(mload(0x1c80), mload(0xbe0), f_q))
mstore(0x1cc0, mulmod(mload(0x1ca0), mload(0xbe0), f_q))
mstore(0x1ce0, mulmod(1, mload(0xbe0), f_q))
mstore(0x1d00, mulmod(1, mload(0x1c80), f_q))
mstore(0x1d20, mulmod(1, mload(0x1ca0), f_q))
mstore(0x1d40, mulmod(mload(0x1c60), mload(0xc00), f_q))
mstore(0x1d60, mulmod(mload(0x960), mload(0x520), f_q))
mstore(0x1d80, mulmod(mload(0x1d60), mload(0x520), f_q))
mstore(0x1da0, mulmod(mload(0x520), 2785514556381676080176937710880804108647911392478702105860685610379369825016, f_q))
mstore(0x1dc0, addmod(mload(0x8e0), sub(f_q, mload(0x1da0)), f_q))
mstore(0x1de0, mulmod(mload(0x520), 1, f_q))
mstore(0x1e00, addmod(mload(0x8e0), sub(f_q, mload(0x1de0)), f_q))
mstore(0x1e20, mulmod(mload(0x520), 1426404432721484388505361748317961535523355871255605456897797744433766488507, f_q))
mstore(0x1e40, addmod(mload(0x8e0), sub(f_q, mload(0x1e20)), f_q))
mstore(0x1e60, mulmod(mload(0x520), 19032961837237948602743626455740240236231119053033140765040043513661803148152, f_q))
mstore(0x1e80, addmod(mload(0x8e0), sub(f_q, mload(0x1e60)), f_q))
mstore(0x1ea0, mulmod(mload(0x520), 3766081621734395783232337525162072736827576297943013392955872170138036189193, f_q))
mstore(0x1ec0, addmod(mload(0x8e0), sub(f_q, mload(0x1ea0)), f_q))
mstore(0x1ee0, mulmod(12142985201493934370659158242092015678465417407805993602870272259656026591649, mload(0x1d60), f_q))
mstore(0x1f00, mulmod(mload(0x1ee0), 1, f_q))
{
            let result := mulmod(mload(0x8e0), mload(0x1ee0), f_q)
result := addmod(mulmod(mload(0x520), sub(f_q, mload(0x1f00)), f_q), result, f_q)
mstore(7968, result)
        }
mstore(0x1f40, mulmod(12858672892267984631233883117647866851148059157064290846881981435700301865966, mload(0x1d60), f_q))
mstore(0x1f60, mulmod(mload(0x1f40), 1426404432721484388505361748317961535523355871255605456897797744433766488507, f_q))
{
            let result := mulmod(mload(0x8e0), mload(0x1f40), f_q)
result := addmod(mulmod(mload(0x520), sub(f_q, mload(0x1f60)), f_q), result, f_q)
mstore(8064, result)
        }
mstore(0x1fa0, mulmod(20880316823902385764034220950270964645276820671488089374347912013802613180902, mload(0x1d60), f_q))
mstore(0x1fc0, mulmod(mload(0x1fa0), 19032961837237948602743626455740240236231119053033140765040043513661803148152, f_q))
{
            let result := mulmod(mload(0x8e0), mload(0x1fa0), f_q)
result := addmod(mulmod(mload(0x520), sub(f_q, mload(0x1fc0)), f_q), result, f_q)
mstore(8160, result)
        }
mstore(0x2000, mulmod(17575202995145968412995467587554373308969396527144859871466654432792864477050, mload(0x1d60), f_q))
mstore(0x2020, mulmod(mload(0x2000), 3766081621734395783232337525162072736827576297943013392955872170138036189193, f_q))
{
            let result := mulmod(mload(0x8e0), mload(0x2000), f_q)
result := addmod(mulmod(mload(0x520), sub(f_q, mload(0x2020)), f_q), result, f_q)
mstore(8256, result)
        }
mstore(0x2060, mulmod(1, mload(0x1e00), f_q))
mstore(0x2080, mulmod(mload(0x2060), mload(0x1e40), f_q))
mstore(0x20a0, mulmod(mload(0x2080), mload(0x1e80), f_q))
mstore(0x20c0, mulmod(mload(0x20a0), mload(0x1ec0), f_q))
mstore(0x20e0, mulmod(20461838439117790833741043996939313553025008529160428886800406442142042007111, mload(0x520), f_q))
mstore(0x2100, mulmod(mload(0x20e0), 1, f_q))
{
            let result := mulmod(mload(0x8e0), mload(0x20e0), f_q)
result := addmod(mulmod(mload(0x520), sub(f_q, mload(0x2100)), f_q), result, f_q)
mstore(8480, result)
        }
mstore(0x2140, mulmod(1426404432721484388505361748317961535523355871255605456897797744433766488506, mload(0x520), f_q))
mstore(0x2160, mulmod(mload(0x2140), 1426404432721484388505361748317961535523355871255605456897797744433766488507, f_q))
{
            let result := mulmod(mload(0x8e0), mload(0x2140), f_q)
result := addmod(mulmod(mload(0x520), sub(f_q, mload(0x2160)), f_q), result, f_q)
mstore(8576, result)
        }
mstore(0x21a0, mulmod(19102728315457599142069468034376470979900453007937332237837518576196438670602, mload(0x520), f_q))
mstore(0x21c0, mulmod(mload(0x21a0), 1, f_q))
{
            let result := mulmod(mload(0x8e0), mload(0x21a0), f_q)
result := addmod(mulmod(mload(0x520), sub(f_q, mload(0x21c0)), f_q), result, f_q)
mstore(8672, result)
        }
mstore(0x2200, mulmod(2785514556381676080176937710880804108647911392478702105860685610379369825015, mload(0x520), f_q))
mstore(0x2220, mulmod(mload(0x2200), 2785514556381676080176937710880804108647911392478702105860685610379369825016, f_q))
{
            let result := mulmod(mload(0x8e0), mload(0x2200), f_q)
result := addmod(mulmod(mload(0x520), sub(f_q, mload(0x2220)), f_q), result, f_q)
mstore(8768, result)
        }
mstore(0x2260, mulmod(mload(0x2060), mload(0x1dc0), f_q))
{
            let result := mulmod(mload(0x8e0), 1, f_q)
result := addmod(mulmod(mload(0x520), 21888242871839275222246405745257275088548364400416034343698204186575808495616, f_q), result, f_q)
mstore(8832, result)
        }
{
            let prod := mload(0x1f20)

                prod := mulmod(mload(0x1f80), prod, f_q)
                mstore(0x22a0, prod)
            
                prod := mulmod(mload(0x1fe0), prod, f_q)
                mstore(0x22c0, prod)
            
                prod := mulmod(mload(0x2040), prod, f_q)
                mstore(0x22e0, prod)
            
                prod := mulmod(mload(0x2120), prod, f_q)
                mstore(0x2300, prod)
            
                prod := mulmod(mload(0x2180), prod, f_q)
                mstore(0x2320, prod)
            
                prod := mulmod(mload(0x2080), prod, f_q)
                mstore(0x2340, prod)
            
                prod := mulmod(mload(0x21e0), prod, f_q)
                mstore(0x2360, prod)
            
                prod := mulmod(mload(0x2240), prod, f_q)
                mstore(0x2380, prod)
            
                prod := mulmod(mload(0x2260), prod, f_q)
                mstore(0x23a0, prod)
            
                prod := mulmod(mload(0x2280), prod, f_q)
                mstore(0x23c0, prod)
            
                prod := mulmod(mload(0x2060), prod, f_q)
                mstore(0x23e0, prod)
            
        }
mstore(0x2420, 32)
mstore(0x2440, 32)
mstore(0x2460, 32)
mstore(0x2480, mload(0x23e0))
mstore(0x24a0, 21888242871839275222246405745257275088548364400416034343698204186575808495615)
mstore(0x24c0, 21888242871839275222246405745257275088548364400416034343698204186575808495617)
success := and(eq(staticcall(gas(), 0x5, 0x2420, 0xc0, 0x2400, 0x20), 1), success)
{
            
            let inv := mload(0x2400)
            let v
        
                    v := mload(0x2060)
                    mstore(8288, mulmod(mload(0x23c0), inv, f_q))
                    inv := mulmod(v, inv, f_q)
                
                    v := mload(0x2280)
                    mstore(8832, mulmod(mload(0x23a0), inv, f_q))
                    inv := mulmod(v, inv, f_q)
                
                    v := mload(0x2260)
                    mstore(8800, mulmod(mload(0x2380), inv, f_q))
                    inv := mulmod(v, inv, f_q)
                
                    v := mload(0x2240)
                    mstore(8768, mulmod(mload(0x2360), inv, f_q))
                    inv := mulmod(v, inv, f_q)
                
                    v := mload(0x21e0)
                    mstore(8672, mulmod(mload(0x2340), inv, f_q))
                    inv := mulmod(v, inv, f_q)
                
                    v := mload(0x2080)
                    mstore(8320, mulmod(mload(0x2320), inv, f_q))
                    inv := mulmod(v, inv, f_q)
                
                    v := mload(0x2180)
                    mstore(8576, mulmod(mload(0x2300), inv, f_q))
                    inv := mulmod(v, inv, f_q)
                
                    v := mload(0x2120)
                    mstore(8480, mulmod(mload(0x22e0), inv, f_q))
                    inv := mulmod(v, inv, f_q)
                
                    v := mload(0x2040)
                    mstore(8256, mulmod(mload(0x22c0), inv, f_q))
                    inv := mulmod(v, inv, f_q)
                
                    v := mload(0x1fe0)
                    mstore(8160, mulmod(mload(0x22a0), inv, f_q))
                    inv := mulmod(v, inv, f_q)
                
                    v := mload(0x1f80)
                    mstore(8064, mulmod(mload(0x1f20), inv, f_q))
                    inv := mulmod(v, inv, f_q)
                mstore(0x1f20, inv)

        }
{
            let result := mload(0x1f20)
result := addmod(mload(0x1f80), result, f_q)
result := addmod(mload(0x1fe0), result, f_q)
result := addmod(mload(0x2040), result, f_q)
mstore(9440, result)
        }
mstore(0x2500, mulmod(mload(0x20c0), mload(0x2080), f_q))
{
            let result := mload(0x2120)
result := addmod(mload(0x2180), result, f_q)
mstore(9504, result)
        }
mstore(0x2540, mulmod(mload(0x20c0), mload(0x2260), f_q))
{
            let result := mload(0x21e0)
result := addmod(mload(0x2240), result, f_q)
mstore(9568, result)
        }
mstore(0x2580, mulmod(mload(0x20c0), mload(0x2060), f_q))
{
            let result := mload(0x2280)
mstore(9632, result)
        }
{
            let prod := mload(0x24e0)

                prod := mulmod(mload(0x2520), prod, f_q)
                mstore(0x25c0, prod)
            
                prod := mulmod(mload(0x2560), prod, f_q)
                mstore(0x25e0, prod)
            
                prod := mulmod(mload(0x25a0), prod, f_q)
                mstore(0x2600, prod)
            
        }
mstore(0x2640, 32)
mstore(0x2660, 32)
mstore(0x2680, 32)
mstore(0x26a0, mload(0x2600))
mstore(0x26c0, 21888242871839275222246405745257275088548364400416034343698204186575808495615)
mstore(0x26e0, 21888242871839275222246405745257275088548364400416034343698204186575808495617)
success := and(eq(staticcall(gas(), 0x5, 0x2640, 0xc0, 0x2620, 0x20), 1), success)
{
            
            let inv := mload(0x2620)
            let v
        
                    v := mload(0x25a0)
                    mstore(9632, mulmod(mload(0x25e0), inv, f_q))
                    inv := mulmod(v, inv, f_q)
                
                    v := mload(0x2560)
                    mstore(9568, mulmod(mload(0x25c0), inv, f_q))
                    inv := mulmod(v, inv, f_q)
                
                    v := mload(0x2520)
                    mstore(9504, mulmod(mload(0x24e0), inv, f_q))
                    inv := mulmod(v, inv, f_q)
                mstore(0x24e0, inv)

        }
mstore(0x2700, mulmod(mload(0x2500), mload(0x2520), f_q))
mstore(0x2720, mulmod(mload(0x2540), mload(0x2560), f_q))
mstore(0x2740, mulmod(mload(0x2580), mload(0x25a0), f_q))
mstore(0x2760, mulmod(mload(0x7e0), mload(0x7e0), f_q))
mstore(0x2780, mulmod(mload(0x2760), mload(0x7e0), f_q))
mstore(0x27a0, mulmod(mload(0x2780), mload(0x7e0), f_q))
mstore(0x27c0, mulmod(mload(0x27a0), mload(0x7e0), f_q))
mstore(0x27e0, mulmod(mload(0x27c0), mload(0x7e0), f_q))
mstore(0x2800, mulmod(mload(0x27e0), mload(0x7e0), f_q))
mstore(0x2820, mulmod(mload(0x2800), mload(0x7e0), f_q))
mstore(0x2840, mulmod(mload(0x2820), mload(0x7e0), f_q))
mstore(0x2860, mulmod(mload(0x2840), mload(0x7e0), f_q))
mstore(0x2880, mulmod(mload(0x840), mload(0x840), f_q))
mstore(0x28a0, mulmod(mload(0x2880), mload(0x840), f_q))
mstore(0x28c0, mulmod(mload(0x28a0), mload(0x840), f_q))
{
            let result := mulmod(mload(0x560), mload(0x1f20), f_q)
result := addmod(mulmod(mload(0x580), mload(0x1f80), f_q), result, f_q)
result := addmod(mulmod(mload(0x5a0), mload(0x1fe0), f_q), result, f_q)
result := addmod(mulmod(mload(0x5c0), mload(0x2040), f_q), result, f_q)
mstore(10464, result)
        }
mstore(0x2900, mulmod(mload(0x28e0), mload(0x24e0), f_q))
mstore(0x2920, mulmod(sub(f_q, mload(0x2900)), 1, f_q))
mstore(0x2940, mulmod(mload(0x2920), 1, f_q))
mstore(0x2960, mulmod(1, mload(0x2500), f_q))
{
            let result := mulmod(mload(0x6e0), mload(0x2120), f_q)
result := addmod(mulmod(mload(0x700), mload(0x2180), f_q), result, f_q)
mstore(10624, result)
        }
mstore(0x29a0, mulmod(mload(0x2980), mload(0x2700), f_q))
mstore(0x29c0, mulmod(sub(f_q, mload(0x29a0)), 1, f_q))
mstore(0x29e0, mulmod(mload(0x2960), 1, f_q))
{
            let result := mulmod(mload(0x720), mload(0x2120), f_q)
result := addmod(mulmod(mload(0x740), mload(0x2180), f_q), result, f_q)
mstore(10752, result)
        }
mstore(0x2a20, mulmod(mload(0x2a00), mload(0x2700), f_q))
mstore(0x2a40, mulmod(sub(f_q, mload(0x2a20)), mload(0x7e0), f_q))
mstore(0x2a60, mulmod(mload(0x2960), mload(0x7e0), f_q))
mstore(0x2a80, addmod(mload(0x29c0), mload(0x2a40), f_q))
mstore(0x2aa0, mulmod(mload(0x2a80), mload(0x840), f_q))
mstore(0x2ac0, mulmod(mload(0x29e0), mload(0x840), f_q))
mstore(0x2ae0, mulmod(mload(0x2a60), mload(0x840), f_q))
mstore(0x2b00, addmod(mload(0x2940), mload(0x2aa0), f_q))
mstore(0x2b20, mulmod(1, mload(0x2540), f_q))
{
            let result := mulmod(mload(0x760), mload(0x21e0), f_q)
result := addmod(mulmod(mload(0x780), mload(0x2240), f_q), result, f_q)
mstore(11072, result)
        }
mstore(0x2b60, mulmod(mload(0x2b40), mload(0x2720), f_q))
mstore(0x2b80, mulmod(sub(f_q, mload(0x2b60)), 1, f_q))
mstore(0x2ba0, mulmod(mload(0x2b20), 1, f_q))
mstore(0x2bc0, mulmod(mload(0x2b80), mload(0x2880), f_q))
mstore(0x2be0, mulmod(mload(0x2ba0), mload(0x2880), f_q))
mstore(0x2c00, addmod(mload(0x2b00), mload(0x2bc0), f_q))
mstore(0x2c20, mulmod(1, mload(0x2580), f_q))
{
            let result := mulmod(mload(0x7a0), mload(0x2280), f_q)
mstore(11328, result)
        }
mstore(0x2c60, mulmod(mload(0x2c40), mload(0x2740), f_q))
mstore(0x2c80, mulmod(sub(f_q, mload(0x2c60)), 1, f_q))
mstore(0x2ca0, mulmod(mload(0x2c20), 1, f_q))
{
            let result := mulmod(mload(0x5e0), mload(0x2280), f_q)
mstore(11456, result)
        }
mstore(0x2ce0, mulmod(mload(0x2cc0), mload(0x2740), f_q))
mstore(0x2d00, mulmod(sub(f_q, mload(0x2ce0)), mload(0x7e0), f_q))
mstore(0x2d20, mulmod(mload(0x2c20), mload(0x7e0), f_q))
mstore(0x2d40, addmod(mload(0x2c80), mload(0x2d00), f_q))
{
            let result := mulmod(mload(0x600), mload(0x2280), f_q)
mstore(11616, result)
        }
mstore(0x2d80, mulmod(mload(0x2d60), mload(0x2740), f_q))
mstore(0x2da0, mulmod(sub(f_q, mload(0x2d80)), mload(0x2760), f_q))
mstore(0x2dc0, mulmod(mload(0x2c20), mload(0x2760), f_q))
mstore(0x2de0, addmod(mload(0x2d40), mload(0x2da0), f_q))
{
            let result := mulmod(mload(0x620), mload(0x2280), f_q)
mstore(11776, result)
        }
mstore(0x2e20, mulmod(mload(0x2e00), mload(0x2740), f_q))
mstore(0x2e40, mulmod(sub(f_q, mload(0x2e20)), mload(0x2780), f_q))
mstore(0x2e60, mulmod(mload(0x2c20), mload(0x2780), f_q))
mstore(0x2e80, addmod(mload(0x2de0), mload(0x2e40), f_q))
{
            let result := mulmod(mload(0x640), mload(0x2280), f_q)
mstore(11936, result)
        }
mstore(0x2ec0, mulmod(mload(0x2ea0), mload(0x2740), f_q))
mstore(0x2ee0, mulmod(sub(f_q, mload(0x2ec0)), mload(0x27a0), f_q))
mstore(0x2f00, mulmod(mload(0x2c20), mload(0x27a0), f_q))
mstore(0x2f20, addmod(mload(0x2e80), mload(0x2ee0), f_q))
{
            let result := mulmod(mload(0x680), mload(0x2280), f_q)
mstore(12096, result)
        }
mstore(0x2f60, mulmod(mload(0x2f40), mload(0x2740), f_q))
mstore(0x2f80, mulmod(sub(f_q, mload(0x2f60)), mload(0x27c0), f_q))
mstore(0x2fa0, mulmod(mload(0x2c20), mload(0x27c0), f_q))
mstore(0x2fc0, addmod(mload(0x2f20), mload(0x2f80), f_q))
{
            let result := mulmod(mload(0x6a0), mload(0x2280), f_q)
mstore(12256, result)
        }
mstore(0x3000, mulmod(mload(0x2fe0), mload(0x2740), f_q))
mstore(0x3020, mulmod(sub(f_q, mload(0x3000)), mload(0x27e0), f_q))
mstore(0x3040, mulmod(mload(0x2c20), mload(0x27e0), f_q))
mstore(0x3060, addmod(mload(0x2fc0), mload(0x3020), f_q))
{
            let result := mulmod(mload(0x6c0), mload(0x2280), f_q)
mstore(12416, result)
        }
mstore(0x30a0, mulmod(mload(0x3080), mload(0x2740), f_q))
mstore(0x30c0, mulmod(sub(f_q, mload(0x30a0)), mload(0x2800), f_q))
mstore(0x30e0, mulmod(mload(0x2c20), mload(0x2800), f_q))
mstore(0x3100, addmod(mload(0x3060), mload(0x30c0), f_q))
mstore(0x3120, mulmod(mload(0x1ce0), mload(0x2580), f_q))
mstore(0x3140, mulmod(mload(0x1d00), mload(0x2580), f_q))
mstore(0x3160, mulmod(mload(0x1d20), mload(0x2580), f_q))
{
            let result := mulmod(mload(0x1d40), mload(0x2280), f_q)
mstore(12672, result)
        }
mstore(0x31a0, mulmod(mload(0x3180), mload(0x2740), f_q))
mstore(0x31c0, mulmod(sub(f_q, mload(0x31a0)), mload(0x2820), f_q))
mstore(0x31e0, mulmod(mload(0x2c20), mload(0x2820), f_q))
mstore(0x3200, mulmod(mload(0x3120), mload(0x2820), f_q))
mstore(0x3220, mulmod(mload(0x3140), mload(0x2820), f_q))
mstore(0x3240, mulmod(mload(0x3160), mload(0x2820), f_q))
mstore(0x3260, addmod(mload(0x3100), mload(0x31c0), f_q))
{
            let result := mulmod(mload(0x660), mload(0x2280), f_q)
mstore(12928, result)
        }
mstore(0x32a0, mulmod(mload(0x3280), mload(0x2740), f_q))
mstore(0x32c0, mulmod(sub(f_q, mload(0x32a0)), mload(0x2840), f_q))
mstore(0x32e0, mulmod(mload(0x2c20), mload(0x2840), f_q))
mstore(0x3300, addmod(mload(0x3260), mload(0x32c0), f_q))
mstore(0x3320, mulmod(mload(0x3300), mload(0x28a0), f_q))
mstore(0x3340, mulmod(mload(0x2ca0), mload(0x28a0), f_q))
mstore(0x3360, mulmod(mload(0x2d20), mload(0x28a0), f_q))
mstore(0x3380, mulmod(mload(0x2dc0), mload(0x28a0), f_q))
mstore(0x33a0, mulmod(mload(0x2e60), mload(0x28a0), f_q))
mstore(0x33c0, mulmod(mload(0x2f00), mload(0x28a0), f_q))
mstore(0x33e0, mulmod(mload(0x2fa0), mload(0x28a0), f_q))
mstore(0x3400, mulmod(mload(0x3040), mload(0x28a0), f_q))
mstore(0x3420, mulmod(mload(0x30e0), mload(0x28a0), f_q))
mstore(0x3440, mulmod(mload(0x31e0), mload(0x28a0), f_q))
mstore(0x3460, mulmod(mload(0x3200), mload(0x28a0), f_q))
mstore(0x3480, mulmod(mload(0x3220), mload(0x28a0), f_q))
mstore(0x34a0, mulmod(mload(0x3240), mload(0x28a0), f_q))
mstore(0x34c0, mulmod(mload(0x32e0), mload(0x28a0), f_q))
mstore(0x34e0, addmod(mload(0x2c00), mload(0x3320), f_q))
mstore(0x3500, mulmod(1, mload(0x20c0), f_q))
mstore(0x3520, mulmod(1, mload(0x8e0), f_q))
mstore(0x3540, 0x0000000000000000000000000000000000000000000000000000000000000001)
                    mstore(0x3560, 0x0000000000000000000000000000000000000000000000000000000000000002)
mstore(0x3580, mload(0x34e0))
success := and(eq(staticcall(gas(), 0x7, 0x3540, 0x60, 0x3540, 0x40), 1), success)
mstore(0x35a0, mload(0x3540))
                    mstore(0x35c0, mload(0x3560))
mstore(0x35e0, mload(0x100))
                    mstore(0x3600, mload(0x120))
success := and(eq(staticcall(gas(), 0x6, 0x35a0, 0x80, 0x35a0, 0x40), 1), success)
mstore(0x3620, mload(0x2e0))
                    mstore(0x3640, mload(0x300))
mstore(0x3660, mload(0x2ac0))
success := and(eq(staticcall(gas(), 0x7, 0x3620, 0x60, 0x3620, 0x40), 1), success)
mstore(0x3680, mload(0x35a0))
                    mstore(0x36a0, mload(0x35c0))
mstore(0x36c0, mload(0x3620))
                    mstore(0x36e0, mload(0x3640))
success := and(eq(staticcall(gas(), 0x6, 0x3680, 0x80, 0x3680, 0x40), 1), success)
mstore(0x3700, mload(0x320))
                    mstore(0x3720, mload(0x340))
mstore(0x3740, mload(0x2ae0))
success := and(eq(staticcall(gas(), 0x7, 0x3700, 0x60, 0x3700, 0x40), 1), success)
mstore(0x3760, mload(0x3680))
                    mstore(0x3780, mload(0x36a0))
mstore(0x37a0, mload(0x3700))
                    mstore(0x37c0, mload(0x3720))
success := and(eq(staticcall(gas(), 0x6, 0x3760, 0x80, 0x3760, 0x40), 1), success)
mstore(0x37e0, mload(0x1a0))
                    mstore(0x3800, mload(0x1c0))
mstore(0x3820, mload(0x2be0))
success := and(eq(staticcall(gas(), 0x7, 0x37e0, 0x60, 0x37e0, 0x40), 1), success)
mstore(0x3840, mload(0x3760))
                    mstore(0x3860, mload(0x3780))
mstore(0x3880, mload(0x37e0))
                    mstore(0x38a0, mload(0x3800))
success := and(eq(staticcall(gas(), 0x6, 0x3840, 0x80, 0x3840, 0x40), 1), success)
mstore(0x38c0, mload(0x1e0))
                    mstore(0x38e0, mload(0x200))
mstore(0x3900, mload(0x3340))
success := and(eq(staticcall(gas(), 0x7, 0x38c0, 0x60, 0x38c0, 0x40), 1), success)
mstore(0x3920, mload(0x3840))
                    mstore(0x3940, mload(0x3860))
mstore(0x3960, mload(0x38c0))
                    mstore(0x3980, mload(0x38e0))
success := and(eq(staticcall(gas(), 0x6, 0x3920, 0x80, 0x3920, 0x40), 1), success)
mstore(0x39a0, 0x2d164578a49f5bf211d1760b786dcd3bf153c90656690d0ed62aa650997ac722)
                    mstore(0x39c0, 0x1ab7fc5dfa2a80f3e6d04f6c75ca2c237c8d46a5d73b1a02c98964a7dc8cc8d2)
mstore(0x39e0, mload(0x3360))
success := and(eq(staticcall(gas(), 0x7, 0x39a0, 0x60, 0x39a0, 0x40), 1), success)
mstore(0x3a00, mload(0x3920))
                    mstore(0x3a20, mload(0x3940))
mstore(0x3a40, mload(0x39a0))
                    mstore(0x3a60, mload(0x39c0))
success := and(eq(staticcall(gas(), 0x6, 0x3a00, 0x80, 0x3a00, 0x40), 1), success)
mstore(0x3a80, 0x17b9541314a49b7e1494dbb9b56c0fe5a2a22b5f40e308f0845c7d5b8700c529)
                    mstore(0x3aa0, 0x1d95155e21064d16f1b5766a5ce76bbae69b692527d80618b8fdf4191ce081c7)
mstore(0x3ac0, mload(0x3380))
success := and(eq(staticcall(gas(), 0x7, 0x3a80, 0x60, 0x3a80, 0x40), 1), success)
mstore(0x3ae0, mload(0x3a00))
                    mstore(0x3b00, mload(0x3a20))
mstore(0x3b20, mload(0x3a80))
                    mstore(0x3b40, mload(0x3aa0))
success := and(eq(staticcall(gas(), 0x6, 0x3ae0, 0x80, 0x3ae0, 0x40), 1), success)
mstore(0x3b60, 0x0cb254069d93cef67cc14d8c8d426baaedc518d66f3c90b2eacf2eb263661e98)
                    mstore(0x3b80, 0x1f595269b9b82643733cffa423930df8b393e3daa4e4087cbd213b15344afc45)
mstore(0x3ba0, mload(0x33a0))
success := and(eq(staticcall(gas(), 0x7, 0x3b60, 0x60, 0x3b60, 0x40), 1), success)
mstore(0x3bc0, mload(0x3ae0))
                    mstore(0x3be0, mload(0x3b00))
mstore(0x3c00, mload(0x3b60))
                    mstore(0x3c20, mload(0x3b80))
success := and(eq(staticcall(gas(), 0x6, 0x3bc0, 0x80, 0x3bc0, 0x40), 1), success)
mstore(0x3c40, 0x1e66e5024141e140fab45706814f18f82ee9fa06ab15891416342936f5d89a3a)
                    mstore(0x3c60, 0x1662361a131bd705b83662a82a98c31d221f2249c348f608fb17cb8139810dfa)
mstore(0x3c80, mload(0x33c0))
success := and(eq(staticcall(gas(), 0x7, 0x3c40, 0x60, 0x3c40, 0x40), 1), success)
mstore(0x3ca0, mload(0x3bc0))
                    mstore(0x3cc0, mload(0x3be0))
mstore(0x3ce0, mload(0x3c40))
                    mstore(0x3d00, mload(0x3c60))
success := and(eq(staticcall(gas(), 0x6, 0x3ca0, 0x80, 0x3ca0, 0x40), 1), success)
mstore(0x3d20, 0x2435710e5b5913e3857d1eb0db2d885e910f4430bbff07c6f280f2867a5d2f30)
                    mstore(0x3d40, 0x24699b1e166ed99d192bd0ac09c546268b744833a97c1d2ab43f28338d543cac)
mstore(0x3d60, mload(0x33e0))
success := and(eq(staticcall(gas(), 0x7, 0x3d20, 0x60, 0x3d20, 0x40), 1), success)
mstore(0x3d80, mload(0x3ca0))
                    mstore(0x3da0, mload(0x3cc0))
mstore(0x3dc0, mload(0x3d20))
                    mstore(0x3de0, mload(0x3d40))
success := and(eq(staticcall(gas(), 0x6, 0x3d80, 0x80, 0x3d80, 0x40), 1), success)
mstore(0x3e00, 0x29222365ed6fa472634157dd4a7fc1c3a8b1c7df9a9db432c1b596e57ce0c4fd)
                    mstore(0x3e20, 0x1566234866025ae800f51f6c82e345844bca87bc288493b8b41a3a8a478bcadd)
mstore(0x3e40, mload(0x3400))
success := and(eq(staticcall(gas(), 0x7, 0x3e00, 0x60, 0x3e00, 0x40), 1), success)
mstore(0x3e60, mload(0x3d80))
                    mstore(0x3e80, mload(0x3da0))
mstore(0x3ea0, mload(0x3e00))
                    mstore(0x3ec0, mload(0x3e20))
success := and(eq(staticcall(gas(), 0x6, 0x3e60, 0x80, 0x3e60, 0x40), 1), success)
mstore(0x3ee0, 0x18e690c00e2a0b3f72f61c343903769405daa7fea04fe09cf2de888a2eadec69)
                    mstore(0x3f00, 0x2aa2efb01196cbb97b7ce3a214adc094098fcc1def2a5621c2b2a07b70205987)
mstore(0x3f20, mload(0x3420))
success := and(eq(staticcall(gas(), 0x7, 0x3ee0, 0x60, 0x3ee0, 0x40), 1), success)
mstore(0x3f40, mload(0x3e60))
                    mstore(0x3f60, mload(0x3e80))
mstore(0x3f80, mload(0x3ee0))
                    mstore(0x3fa0, mload(0x3f00))
success := and(eq(staticcall(gas(), 0x6, 0x3f40, 0x80, 0x3f40, 0x40), 1), success)
mstore(0x3fc0, mload(0x400))
                    mstore(0x3fe0, mload(0x420))
mstore(0x4000, mload(0x3440))
success := and(eq(staticcall(gas(), 0x7, 0x3fc0, 0x60, 0x3fc0, 0x40), 1), success)
mstore(0x4020, mload(0x3f40))
                    mstore(0x4040, mload(0x3f60))
mstore(0x4060, mload(0x3fc0))
                    mstore(0x4080, mload(0x3fe0))
success := and(eq(staticcall(gas(), 0x6, 0x4020, 0x80, 0x4020, 0x40), 1), success)
mstore(0x40a0, mload(0x440))
                    mstore(0x40c0, mload(0x460))
mstore(0x40e0, mload(0x3460))
success := and(eq(staticcall(gas(), 0x7, 0x40a0, 0x60, 0x40a0, 0x40), 1), success)
mstore(0x4100, mload(0x4020))
                    mstore(0x4120, mload(0x4040))
mstore(0x4140, mload(0x40a0))
                    mstore(0x4160, mload(0x40c0))
success := and(eq(staticcall(gas(), 0x6, 0x4100, 0x80, 0x4100, 0x40), 1), success)
mstore(0x4180, mload(0x480))
                    mstore(0x41a0, mload(0x4a0))
mstore(0x41c0, mload(0x3480))
success := and(eq(staticcall(gas(), 0x7, 0x4180, 0x60, 0x4180, 0x40), 1), success)
mstore(0x41e0, mload(0x4100))
                    mstore(0x4200, mload(0x4120))
mstore(0x4220, mload(0x4180))
                    mstore(0x4240, mload(0x41a0))
success := and(eq(staticcall(gas(), 0x6, 0x41e0, 0x80, 0x41e0, 0x40), 1), success)
mstore(0x4260, mload(0x4c0))
                    mstore(0x4280, mload(0x4e0))
mstore(0x42a0, mload(0x34a0))
success := and(eq(staticcall(gas(), 0x7, 0x4260, 0x60, 0x4260, 0x40), 1), success)
mstore(0x42c0, mload(0x41e0))
                    mstore(0x42e0, mload(0x4200))
mstore(0x4300, mload(0x4260))
                    mstore(0x4320, mload(0x4280))
success := and(eq(staticcall(gas(), 0x6, 0x42c0, 0x80, 0x42c0, 0x40), 1), success)
mstore(0x4340, mload(0x360))
                    mstore(0x4360, mload(0x380))
mstore(0x4380, mload(0x34c0))
success := and(eq(staticcall(gas(), 0x7, 0x4340, 0x60, 0x4340, 0x40), 1), success)
mstore(0x43a0, mload(0x42c0))
                    mstore(0x43c0, mload(0x42e0))
mstore(0x43e0, mload(0x4340))
                    mstore(0x4400, mload(0x4360))
success := and(eq(staticcall(gas(), 0x6, 0x43a0, 0x80, 0x43a0, 0x40), 1), success)
mstore(0x4420, mload(0x880))
                    mstore(0x4440, mload(0x8a0))
mstore(0x4460, sub(f_q, mload(0x3500)))
success := and(eq(staticcall(gas(), 0x7, 0x4420, 0x60, 0x4420, 0x40), 1), success)
mstore(0x4480, mload(0x43a0))
                    mstore(0x44a0, mload(0x43c0))
mstore(0x44c0, mload(0x4420))
                    mstore(0x44e0, mload(0x4440))
success := and(eq(staticcall(gas(), 0x6, 0x4480, 0x80, 0x4480, 0x40), 1), success)
mstore(0x4500, mload(0x920))
                    mstore(0x4520, mload(0x940))
mstore(0x4540, mload(0x3520))
success := and(eq(staticcall(gas(), 0x7, 0x4500, 0x60, 0x4500, 0x40), 1), success)
mstore(0x4560, mload(0x4480))
                    mstore(0x4580, mload(0x44a0))
mstore(0x45a0, mload(0x4500))
                    mstore(0x45c0, mload(0x4520))
success := and(eq(staticcall(gas(), 0x6, 0x4560, 0x80, 0x4560, 0x40), 1), success)
mstore(0x45e0, mload(0x4560))
                    mstore(0x4600, mload(0x4580))
mstore(0x4620, 0x198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c2)
            mstore(0x4640, 0x1800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed)
            mstore(0x4660, 0x090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b)
            mstore(0x4680, 0x12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa)
mstore(0x46a0, mload(0x920))
                    mstore(0x46c0, mload(0x940))
mstore(0x46e0, 0x0181624e80f3d6ae28df7e01eaeab1c0e919877a3b8a6b7fbc69a6817d596ea2)
            mstore(0x4700, 0x1783d30dcb12d259bb89098addf6280fa4b653be7a152542a28f7b926e27e648)
            mstore(0x4720, 0x00ae44489d41a0d179e2dfdc03bddd883b7109f8b6ae316a59e815c1a6b35304)
            mstore(0x4740, 0x0b2147ab62a386bd63e6de1522109b8c9588ab466f5aadfde8c41ca3749423ee)
success := and(eq(staticcall(gas(), 0x8, 0x45e0, 0x180, 0x45e0, 0x20), 1), success)
success := and(eq(mload(0x45e0), 1), success)

            // Revert if anything fails
            if iszero(success) { revert(0, 0) }

            // Return empty bytes on success
            return(0, 0)

        }
    }
}
        