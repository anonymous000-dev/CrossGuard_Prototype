import sys
import os
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.dirname(SCRIPT_DIR))
from parserPackage.locator import *



gasConsumption = {
    "functionEntry": 29177,
    "functionExit": 5246,
    "moneyFlow": 27134,
}

gasConsumptionGuard = {
    "EOA": 33,
    "checkAdmin": 2188,

    "ValidatePre": 25184,
    "ValidatePost": 27143,

    "Instrument_prepost": 1661,
    "Instrument_sload": 5972,
    "Instrument_sstore": 1370,
}



benchmark2hack = {
    "bZx2": "0x762881b07feb63c436dee38edd4ff1f7a74c33091e534af56c9f7d49b5ecac15",
    "RevestFi": "0xe0b0c2672b760bef4e2851e91c69c8c0ad135c6987bbf1f43f5846d89e691428",
    "Eminence": "0x3503253131644dd9f52802d071de74e456570374d586ddd640159cf6fb9b8ad8",
    "BeanstalkFarms_interface": "0xcd314668aaa9bbfebaf1a0bd2b6553d01dd58899c508d4729fa7311dc5d33ad7",
    "CreamFi1_1": "0x0016745693d68d734faa408b94cdf2d6c95f511b50f47b03909dc599c1dd9ff6",
    "Yearn1_interface": "0x59faab5a1911618064f1ffa1e4649d85c99cfd9f0d64dcebbc1af7d7630da98b",
    "Opyn": "0xa858463f30a08c6f3410ed456e59277fbe62ff14225754d2bb0b4f6a75fdc8ad",
    "CheeseBank_1": "0x600a869aa3a259158310a233b815ff67ca41eab8961a49918c2031297a02f1cc",
    "Punk_1": "0x597d11c05563611cb4ad4ed4c57ca53bbe3b7d3fefc37d1ef0724ad58904742b",
    "PickleFi": "0xe72d4e7ba9b5af0cf2a8cfb1e30fd9f388df0ab3da79790be842bfbed11087b0",
    "VisorFi": "0x69272d8c84d67d1da2f6425b339192fa472898dce936f24818fda415c1c1ff3f", #"0x6eabef1bf310a1361041d97897c192581cd9870f6a39040cd24d7de2335b4546", 
    "DODO": "0x395675b56370a9f5fe8b32badfa80043f5291443bd6c8273900476880fb5221e",
    "IndexFi": "0x44aad3b853866468161735496a5d9cc961ce5aa872924c5d78673076b1cd95aa",
    "RariCapital1": "0x4764dc6ff19a64fc1b0e57e735661f64d97bc1c44e026317be8765358d0a7392",
    "Harvest1_fUSDT":  "0x0fc6d2ca064fc841bc9b1c1fad1fbb97bcea5c9a1b2b66ef837f1227e06519a6",
    "UmbrellaNetwork":  "0x33479bcfbc792aa0f8103ab0d7a3784788b5b0e1467c81ffbed1b7682660b4fa", 


    "ValueDeFi": "0x46a03488247425f845e444b9c10b52ba3c14927c687d38287c0faddc7471150a",
    "XCarnival": "0x51cbfd46f21afb44da4fa971f220bd28a14530e1d5da5009cfbdfee012e57e35",
    "RariCapital2_3": "0xab486012f21be741c9e674ffda227e30518e8a1e37a5f1d58d0b0d41f6e76530",
    "Warp_interface": "0x8bb8dc5c7c830bac85fa48acad2505e9300a91c3ff239c9517d0cae33b595090",
    "InverseFi": "0x600373f67521324c8068cfd025f121a0843d57ec813411661b07edc5ff781842",
    "CreamFi2_4":  "0x0fe2542079644e107cbf13690eb9c2c65963ccb79089ff96bfaf8dced2331c92",

    "AAVE2": None,
    "Lido2": None,
    "Uniswap2": None,

    "Bedrock_DeFi": "0x725f0d65340c859e0f64e72ca8260220c526c3e0ccde530004160809f6177940",
    "DoughFina": "0x92cdcc732eebf47200ea56123716e337f6ef7d5ad714a2295794fdc6031ebb2e",
    "OnyxDAO": "0x46567c731c4f4f7e27c4ce591f0aebdeb2d9ae1038237a0134de7b13e63d8729",
    
    "BlueberryProtocol": "0xf0464b01d962f714eee9d4392b2494524d0e10ce3eb3723873afd1346b8b06e4",
    "PrismaFi": "0x00c503b595946bccaea3d58025b5f9b3726177bbdc9674e634244135282116c7",
    "PikeFinance": "0xe2912b8bf34d561983f2ae95f34e33ecc7792a2905a3e317fcc98052bce66431",
    "GFOX": "0x12fe79f1de8aed0ba947cec4dce5d33368d649903cb45a5d3e915cc459e751fc",
    "UwULend": "0x242a0fb4fde9de0dc2fd42e8db743cbc197ffa2bf6a036ba0bba303df296408b",

    
        
}


# all addresses in the following must be in lower case
benchmark2targetContracts = {
    "bZx2": ["0x1cf226e9413addaf22412a2e182f9c0de44af002", "0x8b3d70d628ebd30d4a2ea82db95ba2e906c71633", "0xaa6198fe597dfc331471ae7deba026fb299297fc", "0x77f973fcaf871459aa58cd81881ce453759281bc", "0x85ca13d8496b2d22d6518faeb524911e096dd7e0", "0x3756fa458880fa8fe53604101cf31c542ef22f6f", "0x7d8bb0dcfb4f20115883050f45b517459735181b"],
    "RevestFi": ["0xa81bd16aa6f6b25e66965a2f842e9c806c0aa11f", "0xe952bda8c06481506e4731c4f54ced2d4ab81659", "0x2320a28f52334d62622cc2eafa15de55f9987ed9", "0xd721a90dd7e010c8c5e022cc0100c55ac78e0fc4", "0x226124e83868812d3dae87eb3c5f28047e1070b7"],
    "Eminence": ["0x16f6664c16bede5d70818654defef11769d40983", "0x5ade7ae8660293f2ebfcefaba91d141d72d221e8", "0xc08f38f43adb64d16fe9f9efcc2949d9eddec198", "0xb387e90367f1e621e656900ed2a762dc7d71da8c", "0xd77c2ab1cd0faa4b79e16a0e7472cb222a9ee175", "0xe4ffd682380c571a6a07dd8f20b402412e02830e"],
    "BeanstalkFarms_interface": ["0x23d231f37c8f5711468c8abbfbf1757d1f38fda2", "0x3a70dfa7d2262988064a2d051dd47521e43c9bdd", "0x448d330affa0ad31264c2e6a7b5d2bf579608065", "0xf480ee81a54e21be47aa02d0f9e29985bc7667c4", "0xdc59ac4fefa32293a95889dc396682858d52e5db", "0xd652c40fbb3f06d6b58cb9aa9cff063ee63d465d", "0xc1e088fc1323b20bcbee9bd1b9fc9546db5624c5", "0x33b63042865242739ba410ac32ab68723e6cf4b9"],
    "CreamFi1_1": ["0xd06527d5e56a3495252a528c4987003b712860ee", "0x338eee1f7b89ce6272f302bdc4b952c13b221f1d", "0x3d5bc3c8d13dcb8bf317092d84783c2697ae9258", "0x2db6c82ce72c8d7d770ba1b5f5ed0b6e075066d6", "0xbadac56c9aca307079e8b8fc699987aac89813ee", "0x812c0b2a2a0a74f6f6ed620fbd2b67fec7db2190"],
    "Yearn1_interface": ["0xf147b8125d2ef93fb6965db97d6746952a133934", "0xc59601f0cc49baa266891b7fc63d2d5fe097a79d", "0x9ca85572e6a3ebf24dedd195623f188735a5179f", "0xacd43e627e64355f1861cec6d3a6688b31a6f952", "0x9a3a03c614dc467acc3e81275468e033c98d960e", "0x9c211bfa6dc329c5e757a223fb72f5481d676dc1", "0x9e65ad11b299ca0abefc2799ddb6314ef2d91080"],
    "Opyn": ["0x951d51baefb72319d9fbe941e1615938d89abfe2", "0x82151ca501c81108d032c490e25f804787bef3b8", "0x7623a53cbc779dbf44b706a00d4adf1be7e358ec", "0xeb7e15b4e38cbee57a98204d05999c3230d36348"],
    "CheeseBank_1": ["0x026c6ac0179d34e4488f40c52c1486355ce4e755", "0xb54acff1ff7c7de9b0e30ad6d58b941ed22bbb44", "0x7e4956688367fb28de3c0a62193f59b1526a00e7", "0xa04bdb1f11413a84d1f6c1d4d4fed0208f2e68bf", "0xde2289695220531dfcf481fe3554d1c9c3156ba3", "0xa80e737ded94e8d2483ec8d2e52892d9eb94cf1f", "0x833e440332caa07597a5116fbb6163f0e15f743d", "0x4c2a8a820940003cfe4a16294b239c8c55f29695", "0x7f26337348cbaffd3368ab1aad1d111711a0617d", "0x85191476022593a408c472455b57b8346756f144", "0x3c7274679ff9d090889ed8131218bdc871020391", "0x5e181bdde2fa8af7265cb3124735e9a13779c021"],
    "Punk_1": ["0x1f3b04c8c96a31c7920372ffa95371c80a4bfb0d", "0x3bc6aa2d25313ad794b2d67f83f21d341cc3f5fb", "0x929cb86046e421abf7e1e02de7836742654d49d6"],
    "PickleFi": ["0x6949bb624e8e8a90f87cd2058139fcd77d2f3f87", "0x6186e99d9cfb05e1fdf1b442178806e81da21dd8", "0xcd892a97951d46615484359355e3ed88131f829d", "0x6847259b2b3a4c17e7c43c54409810af48ba5210"],
    "VisorFi": ["0x3a84ad5d16adbe566baa6b3dafe39db3d5e261e5", "0xf938424f7210f31df2aee3011291b658f872e91e", "0xc9f27a50f82571c1c8423a42970613b8dbda14ef"],
    "DODO": ["0x2bbd66fc4898242bdbd2583bbe1d76e8b8f71445", "0x051ebd717311350f1684f89335bed4abd083a2b6"],
    "IndexFi": ["0xf00a38376c8668fc1f3cd3daeef42e0e44a7fcdb", "0x120c6956d292b800a835cb935c9dd326bdb4e011", "0x5bd628141c62a901e0a83e630ce5fafa95bbdee4", "0xffde4785e980a99fe10e6a87a67d243664b91b25", "0xfa5a44d3ba93d666bf29c8804a36e725ecac659a", "0xfa6de2697d59e88ed7fc4dfe5a33dac43565ea41"],
    "RariCapital1": ["0x9c0caeb986c003417d21a7daaf30221d61fc1043", "0xcda4770d65b4211364cb870ad6be19e7ef1d65f4", "0xd6e194af3d9674b62d1b30ec676030c23961275e", "0xec260f5a7a729bb3d0c42d292de159b4cb1844a3", "0xed2cd60c0000a990a5ffaf0e7ddc70a37d7c623f", "0xa422890cbbe5eaa8f1c88590fbab7f319d7e24b6", "0xc7a89d73606379f108752bfe4795b69ab4abb94f", "0xb849daff8045fc295af2f6b4e27874914b5911c6"],
    "Harvest1_fUSDT": ["0x053c80ea73dc6941f518a68e2fc52ac45bde7c9c", "0xd8d6ab3d2094d3a0258f4193c5c85fadd44d589a", "0x1c47343ea7135c2ba3b2d24202ad960adafaa81c", "0xf2b223eb3d2b382ead8d85f3c1b7ef87c1d35f3a", "0x2427da81376a0c0a0c654089a951887242d67c92", "0x9b3be0cc5dd26fd0254088d03d8206792715588b", "0x222412af183bceadefd72e4cb1b71f1889953b1c", "0xc95cbe4ca30055c787cb784be99d6a8494d0d197", "0xd55ada00494d96ce1029c201425249f9dfd216cc", "0xfca4416d9def20ac5b6da8b8b322b6559770efbf", "0xf0358e8c3cd5fa238a29301d0bea3d63a17bedbe"],

    "ValueDeFi": ["0x8c2f33b3a580baeb2a1f2d34bcc76e020a54338d", "0x55bf8304c78ba6fe47fd251f37d7beb485f86d26", "0x57cda125d0c7b146a8320614ccd6c55999d15bf2", "0xea48b3f50f3cf2216e34e2e868abc810b729f0e3", "0xb43f0707b2719a5b8ab905d253022c6073a63926", "0xba5d28f4ecee5586d616024c74e4d791e01adee7", "0x8764f2c305b79680cfcc3398a96aedea9260f7ff", "0x98595670e97aa2ec229f366806b37745ad6e92b5", "0x467e9f2caa9b7678ddc29b248cb9fb181907bf3e"],
    "XCarnival": ["0x5e5186d21cbddc8765c4558dbda0bf20b90bf118", "0xb38707e31c813f832ef71c70731ed80b45b85b2d", "0xb7e2300e77d81336307e36ce68d6909e43f4d38a", "0xbd0e1bc09ae52072a9f5d3343b98643ae585e339", "0x222d7b700104c91a2ebbf689ff7b2a35f2541f98", "0xb14b3b9682990ccc16f52eb04146c3ceab01169a"],
    "RariCapital2_3": ["0xb0602af43ca042550ca9da3c33ba3ac375d20df4", "0xe980efb504269ff53f7f4bc92a2bd1e31b43f632", "0x4ef29407a8dbca2f37b7107eab54d6f2a3f2ad60", "0xe102421a85d9c0e71c0ef1870dac658eb43e1493", "0xfea425f0baadf191546cf6f2dbf72357d631ae46", "0xe097783483d1b7527152ef8b150b99b9b2700c8d", "0xa731585ab05fc9f83555cf9bff8f58ee94e18f85", "0x8922c1147e141c055fddfc0ed5a119f3378c8ef8", "0xebe0d1cb6a0b8569929e062d67bfbc07608f0a47", "0x1887118e49e0f4a78bd71b792a49de03504a764d", "0x3f2d1bc6d02522dbcdb216b2e75edddafe04b16f", "0x26267e41ceca7c8e0f143554af707336f27fa051"],
    "Warp_interface": ["0x4a224cd0517f08b26608a2f73bf390b01a6618c8", "0x2261a20c1aa9a73bc35bdb36cd5830d94f2f7ddb", "0xdadd9ba311192d360df13395e137f1e673c91deb", "0x4e9a87ce601618fbf0c5bc415e35a4ac012d3863", "0xf289b48636f6a66f8aea4c2d422a88d4f73b3894", "0x6046c3ab74e6ce761d218b9117d5c63200f4b406", "0xae465fd39b519602ee28f062037f7b9c41fdc8cf", "0x13db1cb418573f4c3a2ea36486f0e421bc0d2427", "0x3c37f97f7d8f705cc230f97a0668f77a0e05d0aa", "0x496b5607e6ef186d5de849a2791fb186e2e94982", "0x97dbf244c17a667d93e29a70b961d7ab9b72d7ed", "0x1b0284391fdf905222b6174ef2cde60ba58d9529", "0x48772565845872fc65c43eccc44d33b25598ca81", "0xba539b9a5c2d412cb10e5770435f362094f9541c", "0x320380c4e463ea9427b49118ddf57f51672743e0", "0xcdb97f4c32f065b8e93cf16bb1e5d198bcf8ca0d", "0xb64dfae5122d70fa932f563c53921fe33967b3e0"],
    "InverseFi": ["0x1637e4e9941d55703a7a5e7807d6ada3f7dcd61b", "0x697b4acaa24430f254224eb794d2a85ba1fa1fb8", "0x39b1df026010b5aea781f90542ee19e900f2db15", "0x4dcf7407ae5c07f8681e1659f626e114a7667339", "0x17786f3813e6ba35343211bd8fe18ec4de14f28b", "0x865377367054516e17014ccded1e7d814edc9ce4", "0xe8929afd47064efd36a7fb51da3f8c5eb40c4cb4", "0x7fcb7dac61ee35b3d4a51117a7c58d53f0a8a670", "0x41d5d79431a913c4ae7d69a668ecdfe5ff9dfb68", "0x210ac53b27f16e20a9aa7d16260f84693390258f", "0x8f0439382359c05ed287acd5170757b76402d93f", "0xde2af899040536884e062d3a334f2dd36f34b4a4"],
    "CreamFi2_4":  ["0x8379baa817c5c5ab929b03ee8e3c48e45018ae41", "0xd06527d5e56a3495252a528c4987003b712860ee", "0x44fbebd2f576670a6c33f6fc0b00aa8c5753b322", "0x851a040fc0dcbb13a272ebc272f2bc2ce1e11c4d", "0x1f9b4756b008106c806c7e64322d7ed3b72cb284", "0x812c0b2a2a0a74f6f6ed620fbd2b67fec7db2190", "0x797aab1ce7c01eb727ab980762ba88e7133d2157", "0x10fdbd1e48ee2fd9336a482d746138ae19e649db", "0xe7db46742c51a7bd64b8d83b8201239d759786be", "0xbadac56c9aca307079e8b8fc699987aac89813ee", "0x8c3b7a4320ba70f8239f83770c4015b5bc4e6f91", "0x9a975fe93cff8b0387b958adb9082b0ed0659ad2", "0x523effc8bfefc2948211a05a905f761cba5e8e9e", "0x299e254a8a165bbeb76d9d69305013329eea3a3b", "0x338eee1f7b89ce6272f302bdc4b952c13b221f1d", "0x3d5bc3c8d13dcb8bf317092d84783c2697ae9258", "0x2a537fa9ffaea8c1a41d3c2b68a9cb791529366d", "0xfd609a03b393f1a1cfcacedabf068cad09a924e2", "0xeff039c3c1d668f408d09dd7b63008622a77532c", "0xcbc1065255cbc3ab41a6868c22d1f1c573ab89fd", "0xe89a6d0509faf730bd707bf868d9a2a744a363c7", "0x228619cca194fbe3ebeb2f835ec1ea5080dafbb2", "0x4112a717edd051f77d834a6703a1ef5e3d73387f", "0x4baa77013ccd6705ab0522853cb0e9d453579dd4"],

    "UmbrellaNetwork": ["0xb3fb1d01b07a706736ca175f827e4f56021b85de"],

    # the following is for preliminary study:
    "Uniswap2": ["0x1f98415757620b543a52e61c46b32eb19261f984" , "0x5ba1e12693dc8f9c48aad8770482f4739beed696", "0xb753548f6e010e7e680ba186f9ca1bdab2e90cf2", "0xbfd8137f7d1516d3ea5ca83523914859ec47f573", "0xb27308f9f90d607463bb33ea1bebb41c27ce5ab6", "0xe592427a0aece92de3edee1f18e0157c05861564", "0x42b24a95702b9986e82d421cc3568932790a48ec", "0x91ae842a5ffd8d12023116943e72a606179294f3", "0xee6a57ec80ea46401049e92587e52f5ec1c24785", "0xc36442b4a4522e871399cd717abdd847ab11fe88", "0xa5644e29708357803b5a882d272c41cc0df92b34", "0x61ffe014ba17989e743c5f6cb21bf9697530b21e", "0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45", "0x000000000022d473030f116ddee9f6b43ac78ba3", "0x3fc91a3afd70395cd496c647d5a6cc9d4b2b7fad", "0xe34139463ba50bd61336e0c446bd8c0867c6fe65"],
    "AAVE2": ["0xc2aacf6553d20d1e9d78e365aaba8032af9c85b0","0x87870bca3f3fd6335c3f4ce8392d69350b4fa4e2","0x64b761d848206f447fe2dd461b0c635ec39ebb27","0x8164cc65827dcfe994ab23944cbc90e0aa80bfcb","0x2f39d218133afab8f2b819b1066c7e434ad94e9e","0xbaa999ac55eace41ccae355c77809e68bb345170","0x7b4eb56e7cd4b454ba8ff71e4518426369a138a3","0x162a7ac02f547ad796ca549f757e2b8d1d9b10a6","0x91c0ea31b49b69ea18607702c5d9ac360bf3de7d","0x893411580e590d62ddbca8a703d61cc4a8c7b2b9","0xc7be5307ba715ce89b152f3df0658295b3dba8e2","0x54586be62e3c3580375ae3723c145253060ca0c2","0x464c71f6c2f760dda6093dcb91c24c39e5d6e18c","0x3d569673daa0575c936c7c67c4e6aeda69cc630c","0xadc0a53095a0af87f3aa29fe0715b5c28016364e","0x02e7b8511831b1b02d9018215a0f8f500ea5c6b3","0x8761e0370f94f68db8eaa731f4fc581f6ad0bd68","0x78f8bd884c3d738b74b420540659c82f392820e0","0xb748952c7bc638f31775245964707bcc5ddfabfc"], 
    "Lido2": ["0xc1d0b3de6792bf6b4b37eccdcc24e45978cfd2eb","0xae7ab96520de3a18e5e111b5eaab095312d7fe84","0x7f39c581f595b53c5cb19bd0b3f8da6c935e2ca0","0x8f73e4c2a6d852bb4ab2a45e6a9cf5715b3228b7","0xfddf38947afb03c621c71b06c9c70bce73f12999","0x55032650b14df07b85bf18a3a3ec8e0af2e028d5","0xae7b191a31f627b4eb1d4dac64eab9976995b433","0xc77f8768774e1c9244beed705c4354f2113cfc09","0x388c818ca8b9251b393131c08a736a67ccb19297","0x889edc2edab5f40e902b864ad4d7ade8e412f9b1","0xb9d7934878b5fb9610b3fe8a5e441e8fad7e293f","0xd15a672319cf0352560ee76d9e89eab0889046d3","0xf95f069f9ad107938f6ba802a3da87892298610e"], 


    # the following is for new hacks
    "Bedrock_DeFi": ["0x004e9c3ef86bc1ca1f0bb5c7662861ee93350568", "0x51a7f889480c57cbeea81614f7d0be2b70db6c5e", "0x047d41f2544b7f63a8e991af2068a363d210d6da"],
    "DoughFina": ["0x9f54e8eaa9658316bb8006e03fff1cb191aafbe6", "0x534a3bb1ecb886ce9e7632e33d97bf22f838d085"],
    "OnyxDAO": ["0x2ccb7d00a9e10d0c3408b5eefb67011abfacb075", "0xcc53f8ff403824a350885a345ed4da649e060369", "0xbd20ae088dee315ace2c08add700775f461fea64", "0xa2cd3d43c775978a96bdbf12d733d5a1ed94fb18", "0xf3354d3e288ce599988e23f9ad814ec1b004d74a", "0x7a89e16cc48432917c948437ac1441b78d133a16", "0x2c6650126b6e0749f977d280c98415ed05894711", "0xee894c051c402301bc19be46c231d2a8e38b0451"],
    
    "BlueberryProtocol": ["0xffadb0bba4379dfabfb20ca6823f6ec439429ec2", "0x643d448cea0d3616f0b32e3718f563b164e7edd2", "0x08830038a6097c10f4a814274d5a68e64648d91c", "0x649127d0800a8c68290129f091564ad2f1d62de1", "0xe61ad5b0e40c856e6c193120bd3fa28a432911b6"],
    "PrismaFi": ["0x4591dbff62656e7859afe5e45f6f47d3669fbb28", "0xcc7218100da61441905e0c327749972e3cbee9ee", "0x72c590349535ad52e6953744cb2a36b409542719"],
    "PikeFinance": ["0xfc7599cffea9de127a9f9c748ccb451a34d2f063"],
    "GFOX": ["0x11a4a5733237082a6c08772927ce0a2b5f8a86b6", "0x8f1cece048cade6b8a05dfa2f90ee4025f4f2662"],
    "UwULend": ["0x2409af0251dcb89ee3dee572629291f9b087c668"]
}


token2DecimalPrices = {
    # bZx2
    "ether": [18, 2000],
    # RENA
    "0x56de8bc61346321d4f2211e3ac3c0a7f00db9b76": [18, 0.338],
    # Eminence
    "0x6b175474e89094c44da98b954eedeac495271d0f": [18, 1],
    # BeanstalkFarms_interface
    "0x6c3f90f043a72fa612cbac8115ee7e52bde6e490": [18, 1],
    "0x5f98805a4e8be255a32880fdec7f6728c6568ba0": [18, 1],
    # CreamFi1_1
    "0xff20817765cb7f73d4bde2e66e067e58d11095c2": [18, 0.029],
    "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2": [18, 2000],
    # Yearn1_interface
    "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48": [6, 1],
    "0xdac17f958d2ee523a2206206994597c13d831ec7": [6, 1],
    # Opyn
    #   0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48
    # CheeseBank_1
    #   0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48
    #   0xdac17f958d2ee523a2206206994597c13d831ec7
    #   0x6b175474e89094c44da98b954eedeac495271d0f
    # Punk_1
    #   0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48
    #   0xdac17f958d2ee523a2206206994597c13d831ec7
    #   0x6b175474e89094c44da98b954eedeac495271d0f
    # PickleFi
    #   0x6b175474e89094c44da98b954eedeac495271d0f
    "0x5d3a536e4d6dbd6114cc1ead35777bab948e3643": [8, 0.02],
    "0xc00e94cb662c3520282e6f5717214004a7f26888": [18, 102],
    # VisorFi
    "0xf938424f7210f31df2aee3011291b658f872e91e": [18, 0.001],
    "0x3a84ad5d16adbe566baa6b3dafe39db3d5e261e5": [18, 0.44],
    # DODO
    # 0xdac17f958d2ee523a2206206994597c13d831ec7
    # IndexFi
    "0xd533a949740bb3306d119cc777fa900ba034cd52": [18, 2.9236879],
    "0x9f8f72aa9304c8b593d555f12ef6589cc3a579a2": [18, 2540.8956],
    "0x6b3595068778dd592e39a122f4f5a5cf09c90fe2": [18, 10.5613],
    "0x1f9840a85d5af5bf1d1762f925bdaddc4201f984": [18, 26.209],
    # 0xc00e94cb662c3520282e6f5717214004a7f26888

    # RariCapital1
    # ether
    # 0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2

    # Harvest1_fUSDT
    # 0xdac17f958d2ee523a2206206994597c13d831ec7
    # 0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48
}

# I think as long as they are not derivative token they should be allowed
benchmark2Tokens = {
    "bZx2": ["ether"],
    "RevestFi": ["0x56de8bc61346321d4f2211e3ac3c0a7f00db9b76"], # RENA token 
    "Eminence": ["0x6b175474e89094c44da98b954eedeac495271d0f"], # DAI
    "BeanstalkFarms_interface": [
        "0x6c3f90f043a72fa612cbac8115ee7e52bde6e490", # 3CRV
        "0x5f98805a4e8be255a32880fdec7f6728c6568ba0", # newly added LUSD
        "0x87898263b6c5babe34b4ec53f22d98430b91e371" # newly added UNI-V2
        ],
    "CreamFi1_1": ["0xff20817765cb7f73d4bde2e66e067e58d11095c2", # AMP token
                   "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2", # wrapped ether
                   "ether"], # or ether
    "Yearn1_interface": ["0x6b175474e89094c44da98b954eedeac495271d0f", # DAI
                         "0x6c3f90f043a72fa612cbac8115ee7e52bde6e490", # 3CRV Token
                         ], 
    "Opyn": ["0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"],   # USDC
    "CheeseBank_1": ["0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48", # USDC
                     "0xdac17f958d2ee523a2206206994597c13d831ec7", # USDT
                     "0x6b175474e89094c44da98b954eedeac495271d0f"],  # DAI
    "Punk_1": ["0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48", # USDC
               "0xdac17f958d2ee523a2206206994597c13d831ec7", # USDT
               "0x6b175474e89094c44da98b954eedeac495271d0f",  # DAI
                "0xf650c3d88d12db855b8bf7d11be6c55a4e07dcc9",  # Compound: cUSDT Token
                "0x39aa39c021dfbae8fac545936693ac917d5e7563",  # Compound: cUSDC Token
                "0x5d3a536e4d6dbd6114cc1ead35777bab948e3643",  # Compound: cDAI Token
    ],
    "PickleFi": ["0x6b175474e89094c44da98b954eedeac495271d0f", # DAI
                 "0x5d3a536e4d6dbd6114cc1ead35777bab948e3643", # cDAI
                 "0xc00e94cb662c3520282e6f5717214004a7f26888", # COMP token
                 ],  
    "VisorFi": ["0xf938424f7210f31df2aee3011291b658f872e91e"], # vVISR (vVISR) derivative token 
    # re-entrancy the same function
    "DODO": ["0xdac17f958d2ee523a2206206994597c13d831ec7"], # USDT
    "IndexFi": ["0xd533a949740bb3306d119cc777fa900ba034cd52", # Curve.fi: CRV Token
                "0x9f8f72aa9304c8b593d555f12ef6589cc3a579a2", # MakerDAO: MKR Token
                "0xc011a73ee8576fb46f5e1c5751ca3b9fe0af2a6f", # Synthetix: Proxy SNX Token
                "0x6b3595068778dd592e39a122f4f5a5cf09c90fe2", # SushiSwap: SUSHI Token
                "0x7fc66500c84a76ad7e9c93437bfc5ac33e2ddae9", # Aave: LEND Token
                "0x1f9840a85d5af5bf1d1762f925bdaddc4201f984", # Uniswap Protocol: UNI token
                "0xc00e94cb662c3520282e6f5717214004a7f26888", # Compound: COMP Token
                "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2", # Wrapped Ether
                ],
    "RariCapital1": ["ether", 
                     "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2", # Wrapped Ether
                     ],
    "Harvest1_fUSDT": ["0xdac17f958d2ee523a2206206994597c13d831ec7", # USDT
                       "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48", # USDC
                    ]
}

def bZx2():
    contracts = ["0x1cf226e9413addaf22412a2e182f9c0de44af002", "0x8b3d70d628ebd30d4a2ea82db95ba2e906c71633", "0xaa6198fe597dfc331471ae7deba026fb299297fc", "0x77f973fcaf871459aa58cd81881ce453759281bc", "0x85ca13d8496b2d22d6518faeb524911e096dd7e0", "0x3756fa458880fa8fe53604101cf31c542ef22f6f", "0x7d8bb0dcfb4f20115883050f45b517459735181b"],
    targetContracts2tokenFlow = {
        '0x85ca13d8496b2d22d6518faeb524911e096dd7e0': [
            [
                locator("borrowTokenFromDeposit", FUNCTION, fromAddr="0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2", name="transferFrom", position=2)
            ],
            [
                locator("burn", FUNCTION, fromAddr="0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2", name="transfer", position=1),
                locator("burnToEther", FUNCTION, name="claimEther", position=1),
                locator("borrowTokenFromDeposit", FUNCTION, name="claimEther", position=1),
                locator("marginTradeFromDeposit", FUNCTION, name="claimEther", position=1)
            ]
        ],
    }
    return contracts, targetContracts2tokenFlow

def RevestFi():
    contracts = ["0xa81bd16aa6f6b25e66965a2f842e9c806c0aa11f", "0xe952bda8c06481506e4731c4f54ced2d4ab81659", "0x2320a28f52334d62622cc2eafa15de55f9987ed9", "0xd721a90dd7e010c8c5e022cc0100c55ac78e0fc4", "0x226124e83868812d3dae87eb3c5f28047e1070b7"],
    targetContracts2tokenFlow = {
        "0xa81bd16aa6f6b25e66965a2f842e9c806c0aa11f": [
            [],
            [
                locator("withdrawToken", FUNCTION, funcAddress = "0x56de8bc61346321d4f2211e3ac3c0a7f00db9b76", name="transfer", position=1),
            ]
        ],
        "0x2320a28f52334d62622cc2eafa15de55f9987ed9": [
            [],
            []
        ]
    }
    return contracts, targetContracts2tokenFlow

def Eminence():
    contracts = ["0x16f6664c16bede5d70818654defef11769d40983", "0x5ade7ae8660293f2ebfcefaba91d141d72d221e8", "0xc08f38f43adb64d16fe9f9efcc2949d9eddec198", "0xb387e90367f1e621e656900ed2a762dc7d71da8c", "0xd77c2ab1cd0faa4b79e16a0e7472cb222a9ee175", "0xe4ffd682380c571a6a07dd8f20b402412e02830e"],
    targetContracts2tokenFlow = {
        '0x5ade7aE8660293F2ebfcEfaba91d141d72d221e8': [
            [locator("buy", FUNCTION, name="transferFrom", position=2)],
            [locator("sell", FUNCTION, name="transfer", position=1)]
        ],
    }
    return contracts, targetContracts2tokenFlow

def BeanstalkFarms_interface():
    contracts = ["0x23d231f37c8f5711468c8abbfbf1757d1f38fda2", "0x3a70dfa7d2262988064a2d051dd47521e43c9bdd", "0x448d330affa0ad31264c2e6a7b5d2bf579608065", "0xf480ee81a54e21be47aa02d0f9e29985bc7667c4", "0xdc59ac4fefa32293a95889dc396682858d52e5db", "0xd652c40fbb3f06d6b58cb9aa9cff063ee63d465d", "0xc1e088fc1323b20bcbee9bd1b9fc9546db5624c5", "0x33b63042865242739ba410ac32ab68723e6cf4b9"],
    targetContracts2tokenFlow = {
        "0x3a70dfa7d2262988064a2d051dd47521e43c9bdd": [
            [
                locator("exchange", FUNCTION, funcAddress = "0x6c3f90f043a72fa612cbac8115ee7e52bde6e490", \
                    name="transferFrom", position=2),
                locator("exchange_underlying", FUNCTION, funcAddress = "0x6c3f90f043a72fa612cbac8115ee7e52bde6e490", \
                    name="transferFrom", position=2),
                locator("add_liquidity", FUNCTION, funcAddress = "0x6c3f90f043a72fa612cbac8115ee7e52bde6e490", \
                    name="transferFrom", position=2),
            ],
            [
                locator("exchange", FUNCTION, funcAddress = "0x6c3f90f043a72fa612cbac8115ee7e52bde6e490", \
                    name="transfer", position=1),
                locator("exchange_underlying", FUNCTION, funcAddress = "0x6c3f90f043a72fa612cbac8115ee7e52bde6e490", \
                    name="transfer", position=1),
                locator("remove_liquidity", FUNCTION, funcAddress = "0x6c3f90f043a72fa612cbac8115ee7e52bde6e490", \
                    name="transfer", position=1),
                locator("remove_liquidity_imbalance", FUNCTION, funcAddress = "0x6c3f90f043a72fa612cbac8115ee7e52bde6e490", \
                    name="transfer", position=1),
                locator("remove_liquidity_one_coin", FUNCTION, funcAddress = "0x6c3f90f043a72fa612cbac8115ee7e52bde6e490", \
                    name="transfer", position=1),
                locator("withdraw_admin_fees", FUNCTION, funcAddress = "0x6c3f90f043a72fa612cbac8115ee7e52bde6e490", \
                    name="transfer", position=1),
            ]
        ],
        "0xc1e088fc1323b20bcbee9bd1b9fc9546db5624c5": [
            [], []
        ]

    }
    return contracts, targetContracts2tokenFlow

def CreamFi1_1():
    contracts = ["0xd06527d5e56a3495252a528c4987003b712860ee", "0x338eee1f7b89ce6272f302bdc4b952c13b221f1d", "0x3d5bc3c8d13dcb8bf317092d84783c2697ae9258", "0x2db6c82ce72c8d7d770ba1b5f5ed0b6e075066d6", "0xbadac56c9aca307079e8b8fc699987aac89813ee", "0x812c0b2a2a0a74f6f6ed620fbd2b67fec7db2190"],
    targetContracts2tokenFlow = {
        '0x2db6c82ce72c8d7d770ba1b5f5ed0b6e075066d6': [
            [
                locator("liquidateBorrow", FUNCTION, funcAddress="0xff20817765cb7f73d4bde2e66e067e58d11095c2", name="transferFrom", position=2),
                locator("repayBorrowBehalf", FUNCTION, funcAddress="0xff20817765cb7f73d4bde2e66e067e58d11095c2", name="transferFrom", position=2),
                locator("repayBorrow", FUNCTION, funcAddress="0xff20817765cb7f73d4bde2e66e067e58d11095c2", name="transferFrom", position=2),
                locator("mint", FUNCTION, funcAddress="0xff20817765cb7f73d4bde2e66e067e58d11095c2", name="transferFrom", position=2),
                locator("_addReserves", FUNCTION, funcAddress="0xff20817765cb7f73d4bde2e66e067e58d11095c2", name="transferFrom", position=2)
            ],
            [
                locator("redeem", FUNCTION, funcAddress="0xff20817765cb7f73d4bde2e66e067e58d11095c2", name="transfer", position=1),
                locator("redeemUnderlying", FUNCTION, funcAddress="0xff20817765cb7f73d4bde2e66e067e58d11095c2", name="transfer", position=1),
                locator("borrow", FUNCTION, funcAddress="0xff20817765cb7f73d4bde2e66e067e58d11095c2", name="transfer", position=1),
                locator("_reduceReserves", FUNCTION, funcAddress="0xff20817765cb7f73d4bde2e66e067e58d11095c2", name="transfer", position=1)
            ]
        ],

        '0xd06527d5e56a3495252a528c4987003b712860ee': [
            [
                locator("liquidateBorrow", SELFCALLVALUE),
                locator("repayBorrowBehalf", SELFCALLVALUE),
                locator("repayBorrow", SELFCALLVALUE),
                locator("mint", SELFCALLVALUE),
                locator("_addReserves", SELFCALLVALUE)
            ],
            [
                locator("_reduceReserves", FALLBACK),
                locator("redeemUnderlying", FALLBACK),
                locator("borrow", FALLBACK),
                locator("_reduceReserves", FALLBACK)
            ]
        ],


    }
    return contracts, targetContracts2tokenFlow

def Yearn1_interface():
    contracts = ["0xf147b8125d2ef93fb6965db97d6746952a133934", "0xc59601f0cc49baa266891b7fc63d2d5fe097a79d", "0x9ca85572e6a3ebf24dedd195623f188735a5179f", "0xacd43e627e64355f1861cec6d3a6688b31a6f952", "0x9a3a03c614dc467acc3e81275468e033c98d960e", "0x9c211bfa6dc329c5e757a223fb72f5481d676dc1", "0x9e65ad11b299ca0abefc2799ddb6314ef2d91080"],
    targetContracts2tokenFlow = {
        '0x9c211bfa6dc329c5e757a223fb72f5481d676dc1': [
            [],
            [
                locator("withdraw", FUNCTION, funcAddress="0x6b175474e89094c44da98b954eedeac495271d0f", name="transfer", position=1),
                locator("withdrawAll", FUNCTION, funcAddress="0x6b175474e89094c44da98b954eedeac495271d0f", name="transfer", position=1),
                locator("migrate", FUNCTION, funcAddress="0x6b175474e89094c44da98b954eedeac495271d0f", name="transfer", position=1),
                locator("forceW", FUNCTION, funcAddress="0x6b175474e89094c44da98b954eedeac495271d0f", name="transfer", position=1),
                locator("forceD", FUNCTION, funcAddress="0x6b175474e89094c44da98b954eedeac495271d0f", name="transfer", position=1),
                locator("deposit", FUNCTION, funcAddress="0x6b175474e89094c44da98b954eedeac495271d0f", name="transfer", position=1)
            ]
        ],

        '0xacd43e627e64355f1861cec6d3a6688b31a6f952': [
            [
                locator("deposit", FUNCTION, funcAddress="0x6b175474e89094c44da98b954eedeac495271d0f", name="transferFrom", position=2),
                locator("depositAll", FUNCTION, funcAddress="0x6b175474e89094c44da98b954eedeac495271d0f", name="transferFrom", position=2)
            ],
            [
                locator("earn", FUNCTION, funcAddress="0x6b175474e89094c44da98b954eedeac495271d0f", name="transfer", position=1),
                locator("harvest", FUNCTION, funcAddress="0x6b175474e89094c44da98b954eedeac495271d0f", name="transfer", position=1),
                locator("withdraw", FUNCTION, funcAddress="0x6b175474e89094c44da98b954eedeac495271d0f", name="transfer", position=1),
                locator("withdrawAll", FUNCTION, funcAddress="0x6b175474e89094c44da98b954eedeac495271d0f", name="transfer", position=1)
            ]
        ],


    }
    return contracts, targetContracts2tokenFlow

def Opyn():
    contracts = ["0x951d51baefb72319d9fbe941e1615938d89abfe2", "0x82151ca501c81108d032c490e25f804787bef3b8", "0x7623a53cbc779dbf44b706a00d4adf1be7e358ec", "0xeb7e15b4e38cbee57a98204d05999c3230d36348"],
    targetContracts2tokenFlow = {
        '0x951d51baefb72319d9fbe941e1615938d89abfe2': [
            [
                locator("sellOTokens", FUNCTION, funcAddress="0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48", name="transferFrom", position=2),
                locator("uniswapBuyOToken", FUNCTION, funcAddress="0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48", name="transferFrom", position=2),
                locator("addERC20Collateral", FUNCTION, funcAddress="0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48", name="transferFrom", position=2),
                locator("exercise", FUNCTION, funcAddress="0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48", name="transferFrom", position=2)
            ],
            [
                locator("transferFee", FUNCTION, funcAddress="0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48", name="transfer", position=1),
                locator("removeCollateral", FUNCTION, funcAddress="0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48", name="transfer", position=1),
                locator("redeemVaultBalance", FUNCTION, funcAddress="0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48", name="transfer", position=1),
                locator("liquidate", FUNCTION, funcAddress="0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48", name="transfer", position=1),
                locator("exercise", FUNCTION, funcAddress="0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48", name="transfer", position=1),
                locator("removeUnderlying", FUNCTION, funcAddress="0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48", name="transfer", position=1)
            ]
        ],

    }
    return contracts, targetContracts2tokenFlow

def CheeseBank_1():
    contracts = ["0x026c6ac0179d34e4488f40c52c1486355ce4e755", "0xb54acff1ff7c7de9b0e30ad6d58b941ed22bbb44", "0x7e4956688367fb28de3c0a62193f59b1526a00e7", "0xa04bdb1f11413a84d1f6c1d4d4fed0208f2e68bf", "0xde2289695220531dfcf481fe3554d1c9c3156ba3", "0xa80e737ded94e8d2483ec8d2e52892d9eb94cf1f", "0x833e440332caa07597a5116fbb6163f0e15f743d", "0x4c2a8a820940003cfe4a16294b239c8c55f29695", "0x7f26337348cbaffd3368ab1aad1d111711a0617d", "0x85191476022593a408c472455b57b8346756f144", "0x3c7274679ff9d090889ed8131218bdc871020391", "0x5e181bdde2fa8af7265cb3124735e9a13779c021"],
    targetContracts2tokenFlow = {
        '0x5E181bDde2fA8af7265CB3124735E9a13779c021': [
            [
                locator("_becomeImplementation", FUNCTION, funcAddress="0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48", name="transferFrom", position=2),
                locator("_setImplementation", FUNCTION, funcAddress="0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48", name="transferFrom", position=2),
                locator("mint", FUNCTION, funcAddress="0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48", name="transferFrom", position=2),
                locator("repayBorrow", FUNCTION, funcAddress="0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48", name="transferFrom", position=2),
                locator("repayBorrowBehalf", FUNCTION, funcAddress="0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48", name="transferFrom", position=2),
                locator("liquidateBorrow", FUNCTION, funcAddress="0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48", name="transferFrom", position=2),
                locator("_addReserves", FUNCTION, funcAddress="0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48", name="transferFrom", position=2)
            ],
            [
                locator("redeem", FUNCTION, funcAddress="0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48", name="transfer", position=1),
                locator("redeemUnderlying", FUNCTION, funcAddress="0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48", name="transfer", position=1),
                locator("borrow", FUNCTION, funcAddress="0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48", name="transfer", position=1),
                locator("_reduceReserves", FUNCTION, funcAddress="0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48", name="transfer", position=1)
            ]
        ],

        '0x4c2a8A820940003cfE4a16294B239C8C55F29695': [
            [
                locator("_becomeImplementation", FUNCTION, funcAddress="0xdac17f958d2ee523a2206206994597c13d831ec7", name="transferFrom", position=2),
                locator("_setImplementation", FUNCTION, funcAddress="0xdac17f958d2ee523a2206206994597c13d831ec7", name="transferFrom", position=2),
                locator("mint", FUNCTION, funcAddress="0xdac17f958d2ee523a2206206994597c13d831ec7", name="transferFrom", position=2),
                locator("repayBorrow", FUNCTION, funcAddress="0xdac17f958d2ee523a2206206994597c13d831ec7", name="transferFrom", position=2),
                locator("repayBorrowBehalf", FUNCTION, funcAddress="0xdac17f958d2ee523a2206206994597c13d831ec7", name="transferFrom", position=2),
                locator("liquidateBorrow", FUNCTION, funcAddress="0xdac17f958d2ee523a2206206994597c13d831ec7", name="transferFrom", position=2),
                locator("_addReserves", FUNCTION, funcAddress="0xdac17f958d2ee523a2206206994597c13d831ec7", name="transferFrom", position=2)
            ],
            [
                locator("redeem", FUNCTION, funcAddress="0xdac17f958d2ee523a2206206994597c13d831ec7", name="transfer", position=1),
                locator("redeemUnderlying", FUNCTION, funcAddress="0xdac17f958d2ee523a2206206994597c13d831ec7", name="transfer", position=1),
                locator("borrow", FUNCTION, funcAddress="0xdac17f958d2ee523a2206206994597c13d831ec7", name="transfer", position=1),
                locator("_reduceReserves", FUNCTION, funcAddress="0xdac17f958d2ee523a2206206994597c13d831ec7", name="transfer", position=1)
            ]
        ],
    
        '0xA80e737Ded94E8D2483ec8d2E52892D9Eb94cF1f': [
            [
                locator("_becomeImplementation", FUNCTION, funcAddress="0x6b175474e89094c44da98b954eedeac495271d0f", name="transferFrom", position=2),
                locator("_setImplementation", FUNCTION, funcAddress="0x6b175474e89094c44da98b954eedeac495271d0f", name="transferFrom", position=2),
                locator("mint", FUNCTION, funcAddress="0x6b175474e89094c44da98b954eedeac495271d0f", name="transferFrom", position=2),
                locator("repayBorrow", FUNCTION, funcAddress="0x6b175474e89094c44da98b954eedeac495271d0f", name="transferFrom", position=2),
                locator("repayBorrowBehalf", FUNCTION, funcAddress="0x6b175474e89094c44da98b954eedeac495271d0f", name="transferFrom", position=2),
                locator("liquidateBorrow", FUNCTION, funcAddress="0x6b175474e89094c44da98b954eedeac495271d0f", name="transferFrom", position=2),
                locator("_addReserves", FUNCTION, funcAddress="0x6b175474e89094c44da98b954eedeac495271d0f", name="transferFrom", position=2)
            ],
            [
                locator("redeem", FUNCTION, funcAddress="0x6b175474e89094c44da98b954eedeac495271d0f", name="transfer", position=1),
                locator("redeemUnderlying", FUNCTION, funcAddress="0x6b175474e89094c44da98b954eedeac495271d0f", name="transfer", position=1),
                locator("borrow", FUNCTION, funcAddress="0x6b175474e89094c44da98b954eedeac495271d0f", name="transfer", position=1),
                locator("_reduceReserves", FUNCTION, funcAddress="0x6b175474e89094c44da98b954eedeac495271d0f", name="transfer", position=1)
            ]
        ],

    }
    return contracts, targetContracts2tokenFlow

def Punk_1():
    contracts = ["0x1f3b04c8c96a31c7920372ffa95371c80a4bfb0d", "0x3bc6aa2d25313ad794b2d67f83f21d341cc3f5fb", "0x929cb86046e421abf7e1e02de7836742654d49d6"],
    targetContracts2tokenFlow = {
        "0x3BC6aA2D25313ad794b2D67f83f21D341cc3f5fb": [
            [],
            [        
                locator("withdrawTo", FUNCTION, fromAddr = "0x3bc6aa2d25313ad794b2d67f83f21d341cc3f5fb", funcAddress = "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48", name="transfer", position=1),
                locator("withdrawToForge", FUNCTION, fromAddr = "0x3bc6aa2d25313ad794b2d67f83f21d341cc3f5fb", funcAddress = "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48", name="transfer", position=1),
            ]
        ],
        "0x1F3b04c8c96A31C7920372FFa95371C80A4bfb0D": [
            [],
            [
                locator("withdrawTo", FUNCTION, fromAddr = "0x1F3b04c8c96A31C7920372FFa95371C80A4bfb0D", funcAddress = "0xdac17f958d2ee523a2206206994597c13d831ec7", name="transfer", position=1),
                locator("withdrawToForge", FUNCTION, fromAddr = "0x1F3b04c8c96A31C7920372FFa95371C80A4bfb0D", funcAddress = "0xdac17f958d2ee523a2206206994597c13d831ec7", name="transfer", position=1),
            ]
        ],
        "0x929cb86046E421abF7e1e02dE7836742654D49d6": [
            [],
            [
                locator("withdrawTo", FUNCTION, fromAddr = "0x929cb86046E421abF7e1e02dE7836742654D49d6", funcAddress = "0x6b175474e89094c44da98b954eedeac495271d0f", name="transfer", position=1),
                locator("withdrawToForge", FUNCTION, fromAddr = "0x929cb86046E421abF7e1e02dE7836742654D49d6", funcAddress = "0x6b175474e89094c44da98b954eedeac495271d0f", name="transfer", position=1),
            ]
        ]
    }
    return contracts, targetContracts2tokenFlow

def PickleFi():
    contracts = ["0x6949bb624e8e8a90f87cd2058139fcd77d2f3f87", "0x6186e99d9cfb05e1fdf1b442178806e81da21dd8", "0xcd892a97951d46615484359355e3ed88131f829d", "0x6847259b2b3a4c17e7c43c54409810af48ba5210"],
    targetContracts2tokenFlow = {
        "0x6847259b2B3A4c17e7c43C54409810aF48bA5210": [
            [
                locator("swapExactJarForJar", FUNCTION, funcAddress = "0x6b175474e89094c44da98b954eedeac495271d0f", \
                    name="transferFrom", position=2),
                locator("deposit", FUNCTION, funcAddress = "0x6b175474e89094c44da98b954eedeac495271d0f", \
                    name="transferFrom", position=2),
                locator("depositAll", FUNCTION, funcAddress = "0x6b175474e89094c44da98b954eedeac495271d0f", \
                    name="transferFrom", position=2),
                locator("harvest", FUNCTION, funcAddress = "0x6b175474e89094c44da98b954eedeac495271d0f", \
                    name="transferFrom", position=2),
                locator("leverageUntil", FUNCTION, funcAddress = "0x6b175474e89094c44da98b954eedeac495271d0f", \
                    name="transferFrom", position=2),
                locator("convertWETHPair", FUNCTION, funcAddress = "0x6b175474e89094c44da98b954eedeac495271d0f", \
                    name="transferFrom", position=2),
                locator("stake", FUNCTION, funcAddress = "0x6b175474e89094c44da98b954eedeac495271d0f", \
                    name="transferFrom", position=2),
                locator("convert", FUNCTION, funcAddress = "0x6b175474e89094c44da98b954eedeac495271d0f", \
                    name="transferFrom", position=2),
            ],
            [
                locator("earn", FUNCTION, funcAddress = "0x6b175474e89094c44da98b954eedeac495271d0f", \
                    name="transfer", position=1),
                locator("yearn", FUNCTION, funcAddress = "0x6b175474e89094c44da98b954eedeac495271d0f", \
                    name="transfer", position=1),
                locator("inCaseTokensGetStuck", FUNCTION, funcAddress = "0x6b175474e89094c44da98b954eedeac495271d0f", \
                    name="transfer", position=1),
                locator("swapExactJarForJar", FUNCTION, funcAddress = "0x6b175474e89094c44da98b954eedeac495271d0f", \
                    name="transfer", position=1),
                locator("convert", FUNCTION, funcAddress = "0x6b175474e89094c44da98b954eedeac495271d0f", \
                    name="transfer", position=1),
                locator("harvest", FUNCTION, funcAddress = "0x6b175474e89094c44da98b954eedeac495271d0f", \
                    name="transfer", position=1),
                locator("withdraw", FUNCTION, funcAddress = "0x6b175474e89094c44da98b954eedeac495271d0f", \
                    name="transfer", position=1),
                locator("claimRewards", FUNCTION, funcAddress = "0x6b175474e89094c44da98b954eedeac495271d0f", \
                    name="transfer", position=1),
                locator("test_staking", FUNCTION, funcAddress = "0x6b175474e89094c44da98b954eedeac495271d0f", \
                    name="transfer", position=1),
                locator("test_jar_converter_curve_curve_0", FUNCTION, funcAddress = "0x6b175474e89094c44da98b954eedeac495271d0f", \
                    name="approve", position=1),
                locator("test_jar_converter_curve_curve_1", FUNCTION, funcAddress = "0x6b175474e89094c44da98b954eedeac495271d0f", \
                    name="approve", position=1),
                locator("test_jar_converter_curve_curve_2", FUNCTION, funcAddress = "0x6b175474e89094c44da98b954eedeac495271d0f", \
                    name="approve", position=1),
                locator("test_jar_converter_curve_curve_3", FUNCTION, funcAddress = "0x6b175474e89094c44da98b954eedeac495271d0f", \
                    name="approve", position=1),
                locator("test_jar_converter_curve_curve_4", FUNCTION, funcAddress = "0x6b175474e89094c44da98b954eedeac495271d0f", \
                    name="approve", position=1),
                locator("test_jar_converter_curve_uni_0_0", FUNCTION, funcAddress = "0x6b175474e89094c44da98b954eedeac495271d0f", \
                    name="approve", position=1),
                locator("test_jar_converter_curve_uni_0_1", FUNCTION, funcAddress = "0x6b175474e89094c44da98b954eedeac495271d0f", \
                        name="approve", position=1),
                locator("test_jar_converter_curve_uni_0_2", FUNCTION, funcAddress = "0x6b175474e89094c44da98b954eedeac495271d0f", \
                        name="approve", position=1),
                locator("test_jar_converter_curve_uni_0_3", FUNCTION, funcAddress = "0x6b175474e89094c44da98b954eedeac495271d0f", \
                        name="approve", position=1),
                locator("test_jar_converter_curve_uni_1_0", FUNCTION, funcAddress = "0x6b175474e89094c44da98b954eedeac495271d0f", \
                        name="approve", position=1),
                locator("test_jar_converter_curve_uni_1_1", FUNCTION, funcAddress = "0x6b175474e89094c44da98b954eedeac495271d0f", \
                        name="approve", position=1),
                locator("test_jar_converter_curve_uni_1_2", FUNCTION, funcAddress = "0x6b175474e89094c44da98b954eedeac495271d0f", \
                        name="approve", position=1),
                locator("test_jar_converter_curve_uni_1_3", FUNCTION, funcAddress = "0x6b175474e89094c44da98b954eedeac495271d0f", \
                        name="approve", position=1),
                locator("test_jar_converter_curve_uni_2_3", FUNCTION, funcAddress = "0x6b175474e89094c44da98b954eedeac495271d0f",
                        name="approve", position=1),
                locator("test_jar_converter_uni_curve_0_0", FUNCTION, funcAddress = "0x6b175474e89094c44da98b954eedeac495271d0f",
                        name="approve", position=1),
                locator("test_jar_converter_uni_curve_1_0", FUNCTION, funcAddress = "0x6b175474e89094c44da98b954eedeac495271d0f",
                        name="approve", position=1),
                locator("test_jar_converter_uni_curve_2_0", FUNCTION, funcAddress = "0x6b175474e89094c44da98b954eedeac495271d0f",
                        name="approve", position=1),
                locator("test_jar_converter_uni_curve_3_0", FUNCTION, funcAddress = "0x6b175474e89094c44da98b954eedeac495271d0f",
                        name="approve", position=1),
                locator("test_jar_converter_uni_curve_0_1", FUNCTION, funcAddress = "0x6b175474e89094c44da98b954eedeac495271d0f",
                        name="approve", position=1),
                locator("test_jar_converter_uni_curve_1_1", FUNCTION, funcAddress = "0x6b175474e89094c44da98b954eedeac495271d0f",
                        name="approve", position=1),
                locator("test_jar_converter_uni_curve_2_1", FUNCTION, funcAddress = "0x6b175474e89094c44da98b954eedeac495271d0f",
                        name="approve", position=1),
                locator("test_jar_converter_uni_curve_3_1", FUNCTION, funcAddress = "0x6b175474e89094c44da98b954eedeac495271d0f",
                        name="approve", position=1),
                locator("test_jar_converter_uni_curve_4_1", FUNCTION, funcAddress = "0x6b175474e89094c44da98b954eedeac495271d0f",
                        name="approve", position=1),
                locator("test_jar_converter_uni_curve_0_2", FUNCTION, funcAddress = "0x6b175474e89094c44da98b954eedeac495271d0f",
                        name="approve", position=1), 
                locator("test_jar_converter_uni_curve_1_2", FUNCTION, funcAddress = "0x6b175474e89094c44da98b954eedeac495271d0f",
                        name="approve", position=1),
                locator("test_jar_converter_uni_curve_2_2", FUNCTION, funcAddress = "0x6b175474e89094c44da98b954eedeac495271d0f",
                        name="approve", position=1),
                locator("test_jar_converter_uni_curve_3_2", FUNCTION, funcAddress = "0x6b175474e89094c44da98b954eedeac495271d0f",
                        name="approve", position=1),
                locator("test_jar_converter_uni_uni_0", FUNCTION, funcAddress = "0x6b175474e89094c44da98b954eedeac495271d0f",
                        name="approve", position=1),
                locator("test_jar_converter_uni_uni_1", FUNCTION, funcAddress = "0x6b175474e89094c44da98b954eedeac495271d0f",
                        name="approve", position=1),
                locator("test_jar_converter_uni_uni_2", FUNCTION, funcAddress = "0x6b175474e89094c44da98b954eedeac495271d0f",
                        name="approve", position=1),
                locator("test_jar_converter_uni_uni_3", FUNCTION, funcAddress = "0x6b175474e89094c44da98b954eedeac495271d0f",
                        name="approve", position=1),
            ]
        ]
    }
    return contracts, targetContracts2tokenFlow

def VisorFi():
    contracts = ["0x3a84ad5d16adbe566baa6b3dafe39db3d5e261e5", "0xf938424f7210f31df2aee3011291b658f872e91e", "0xc9f27a50f82571c1c8423a42970613b8dbda14ef"],
    targetContracts2tokenFlow = {
        "0xc9f27a50f82571c1c8423a42970613b8dbda14ef": [
            [
                locator("deposit", FUNCTION, funcAddress = "0xf938424f7210f31df2aee3011291b658f872e91e", name="transferFrom", position=2), 
            ],
            [
                locator("withdraw", FUNCTION, funcAddress = "0xf938424f7210f31df2aee3011291b658f872e91e", name="transfer", position=1), 
            ]
        ]
    }
    return contracts, targetContracts2tokenFlow

def DODO():
    contracts = ["0x2bbd66fc4898242bdbd2583bbe1d76e8b8f71445", "0x051ebd717311350f1684f89335bed4abd083a2b6"],
    targetContracts2tokenFlow = {
        "0x051ebd717311350f1684f89335bed4abd083a2b6": [
            [],
            [
                locator("sellQuote", FUNCTION, funcAddress = "0xdac17f958d2ee523a2206206994597c13d831ec7", \
                    name="transfer", position=1),
                locator("flashLoan", FUNCTION, funcAddress = "0xdac17f958d2ee523a2206206994597c13d831ec7", \
                    name="transfer", position=1),
                locator("sellShares", FUNCTION, funcAddress = "0xdac17f958d2ee523a2206206994597c13d831ec7", \
                    name="transfer", position=1),
            ]
        ]
    }
    return contracts, targetContracts2tokenFlow

def IndexFi():
    contracts = ["0xf00a38376c8668fc1f3cd3daeef42e0e44a7fcdb", "0x120c6956d292b800a835cb935c9dd326bdb4e011", "0x5bd628141c62a901e0a83e630ce5fafa95bbdee4", "0xffde4785e980a99fe10e6a87a67d243664b91b25", "0xfa5a44d3ba93d666bf29c8804a36e725ecac659a", "0xfa6de2697d59e88ed7fc4dfe5a33dac43565ea41"],
    targetContracts2tokenFlow = {
        '0x5bd628141c62a901e0a83e630ce5fafa95bbdee4': [
            [
                locator("joinPool", FUNCTION, funcAddress="0x1f9840a85d5af5bf1d1762f925bdaddc4201f984", name="transferFrom", position=2),
                locator("joinswapExternAmountIn", FUNCTION, funcAddress="0x1f9840a85d5af5bf1d1762f925bdaddc4201f984", name="transferFrom", position=2),
                locator("joinswapPoolAmountOut", FUNCTION, funcAddress="0x1f9840a85d5af5bf1d1762f925bdaddc4201f984", name="transferFrom", position=2),
                locator("swapExactAmountIn", FUNCTION, funcAddress="0x1f9840a85d5af5bf1d1762f925bdaddc4201f984", name="transferFrom", position=2),
                locator("swapExactAmountOut", FUNCTION, funcAddress="0x1f9840a85d5af5bf1d1762f925bdaddc4201f984", name="transferFrom", position=2)
            ],
            [
                locator("exitPool", FUNCTION, funcAddress="0x1f9840a85d5af5bf1d1762f925bdaddc4201f984", name="transfer", position=1),
                locator("exitswapPoolAmountIn", FUNCTION, funcAddress="0x1f9840a85d5af5bf1d1762f925bdaddc4201f984", name="transfer", position=1),
                locator("exitswapExternAmountOut", FUNCTION, funcAddress="0x1f9840a85d5af5bf1d1762f925bdaddc4201f984", name="transfer", position=1),
                locator("gulp", FUNCTION, funcAddress="0x1f9840a85d5af5bf1d1762f925bdaddc4201f984", name="transfer", position=1),
                locator("swapExactAmountIn", FUNCTION, funcAddress="0x1f9840a85d5af5bf1d1762f925bdaddc4201f984", name="transfer", position=1),
                locator("swapExactAmountOut", FUNCTION, funcAddress="0x1f9840a85d5af5bf1d1762f925bdaddc4201f984", name="transfer", position=1)
            ]
        ],

    }
    return contracts, targetContracts2tokenFlow

def RariCapital1():
    contracts = ["0x9c0caeb986c003417d21a7daaf30221d61fc1043", "0xcda4770d65b4211364cb870ad6be19e7ef1d65f4", "0xd6e194af3d9674b62d1b30ec676030c23961275e", "0xec260f5a7a729bb3d0c42d292de159b4cb1844a3", "0xed2cd60c0000a990a5ffaf0e7ddc70a37d7c623f", "0xa422890cbbe5eaa8f1c88590fbab7f319d7e24b6", "0xc7a89d73606379f108752bfe4795b69ab4abb94f", "0xb849daff8045fc295af2f6b4e27874914b5911c6"],
    targetContracts2tokenFlow = {    
        "0xec260f5a7a729bb3d0c42d292de159b4cb1844a3": [
            [
                locator("deposit", SELFCALLVALUE),
                locator("depositTo", SELFCALLVALUE),
                locator("exchangeAndDeposit", SELFCALLVALUE),
                locator("withdrawAndExchange", SELFCALLVALUE),
            ],
            [
                locator("withdraw", FALLBACK),
                locator("withdrawFrom", FALLBACK),
                locator("withdrawAndExchange", FALLBACK),
                locator("deposit", FALLBACK),
                locator("depositTo", FALLBACK),
            ]
        ]
    }
    return contracts, targetContracts2tokenFlow

def Harvest1_fUSDT():
    contracts = ["0x053c80ea73dc6941f518a68e2fc52ac45bde7c9c", "0xd8d6ab3d2094d3a0258f4193c5c85fadd44d589a", "0x1c47343ea7135c2ba3b2d24202ad960adafaa81c", "0xf2b223eb3d2b382ead8d85f3c1b7ef87c1d35f3a", "0x2427da81376a0c0a0c654089a951887242d67c92", "0x9b3be0cc5dd26fd0254088d03d8206792715588b", "0x222412af183bceadefd72e4cb1b71f1889953b1c", "0xc95cbe4ca30055c787cb784be99d6a8494d0d197", "0xd55ada00494d96ce1029c201425249f9dfd216cc", "0xfca4416d9def20ac5b6da8b8b322b6559770efbf", "0xf0358e8c3cd5fa238a29301d0bea3d63a17bedbe"]  
    targetContracts2tokenFlow = {
        '0x053c80ea73dc6941f518a68e2fc52ac45bde7c9c': [
            [
                locator("deposit", FUNCTION, name="transferFrom", position=2),
                locator("depositFor", FUNCTION, name="transferFrom", position=2)
            ],
            [locator("withdraw", FUNCTION, name="transfer", position=1)]
        ],
        '0xf0358e8c3cd5fa238a29301d0bea3d63a17bedbe': [
            [
                locator("deposit", FUNCTION, name="transferFrom", position=2),
                locator("depositFor", FUNCTION, name="transferFrom", position=2)
            ],
            [locator("withdraw", FUNCTION, name="transfer", position=1)]
        ],
    }
    return contracts, targetContracts2tokenFlow
