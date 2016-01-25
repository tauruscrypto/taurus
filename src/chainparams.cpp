// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "assert.h"

#include "chainparams.h"
#include "main.h"
#include "util.h"

#include <boost/assign/list_of.hpp>

using namespace boost::assign;

struct SeedSpec6 {
    uint8_t addr[16];
    uint16_t port;
};

#include "chainparamsseeds.h"

//
// Main network
//

// Convert the pnSeeds6 array into usable address objects.
static void convertSeed6(std::vector<CAddress> &vSeedsOut, const SeedSpec6 *data, unsigned int count)
{
    // It'll only connect to one or two seed nodes because once it connects,
    // it'll get a pile of addresses with newer timestamps.
    // Seed nodes are given a random 'last seen time' of between one and two
    // weeks ago.
    const int64_t nOneWeek = 7*24*60*60;
    for (unsigned int i = 0; i < count; i++)
    {
        struct in6_addr ip;
        memcpy(&ip, data[i].addr, sizeof(ip));
        CAddress addr(CService(ip, data[i].port));
        addr.nTime = GetTime() - GetRand(nOneWeek) - nOneWeek;
        vSeedsOut.push_back(addr);
    }
}

class CMainParams : public CChainParams {
public:
    CMainParams() {
        // The message start string is designed to be unlikely to occur in normal data.
        // The characters are rarely used upper ASCII, not valid as UTF-8, and produce
        // a large 4-byte int at any alignment.
        pchMessageStart[0] = 0x5a;
        pchMessageStart[1] = 0x2c;
        pchMessageStart[2] = 0x1b;
        pchMessageStart[3] = 0x4a;
        vAlertPubKey = ParseHex("");
        nDefaultPort = 34120;
        nRPCPort = 35120;
        bnProofOfWorkLimit = CBigNum(~uint256(0) >> 16);

  
        const char* pszTimestamp = "Taurus Coin";
        std::vector<CTxIn> vin;
        vin.resize(1);
        vin[0].scriptSig = CScript() << 0 << CBigNum(42) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        std::vector<CTxOut> vout;
        vout.resize(1);
        vout[0].SetEmpty();
        CTransaction txNew(1, 1453581660, vin, vout, 0);
        genesis.vtx.push_back(txNew);
        genesis.hashPrevBlock = 0;
        genesis.hashMerkleRoot = genesis.BuildMerkleTree();
        genesis.nVersion = 1;
        genesis.nTime = 1453581660;
        genesis.nBits = 520159231;
        genesis.nNonce = 36893;

/*
	if (true && genesis.GetHash() != hashGenesisBlock)
                       {
                           printf("Searching for genesis block...\n");
                           uint256 hashTarget = CBigNum().SetCompact(genesis.nBits).getuint256();
                           uint256 thash;

                           while (true)
                           {
                               thash = genesis.GetHash();
                               if (thash <= hashTarget)
                                 break;
                               if ((genesis.nNonce & 0xFFF) == 0)
                               {
                                   printf("nonce %08X: hash = %s (target = %s)\n", genesis.nNonce, thash.ToString().c_str(), hashTarget.ToString().c_str());
                               }
                               ++genesis.nNonce;
                               if (genesis.nNonce == 0)
                               {
                                   printf("NONCE WRAPPED, incrementing time\n");
                                   ++genesis.nTime;
                               }
                           }
                           printf("genesis.nTime = %u \n", genesis.nTime);
                           printf("genesis.nNonce = %u \n", genesis.nNonce);
                           printf("genesis.nVersion = %u \n", genesis.nVersion);
//                           printf("genesis.GetHash = %s\n", genesis.GetHash().ToString().c_str()); //first this, then comment this line out and uncomment the one under.
                           printf("genesis.hashMerkleRoot = %s \n", genesis.hashMerkleRoot.ToString().c_str()); //improvised. worked for me, to find merkle root/
                       }
 */
        hashGenesisBlock = genesis.GetHash();
        assert(hashGenesisBlock == uint256("0x0000bc026d0a164c506186d8b677f92915b9884413a95e5191f8502e53af5b4a"));
        assert(genesis.hashMerkleRoot == uint256("0x52d88a2e1d1c986e0cf067183a4add6092f031af272cb90120fb740a9883052b"));

     	vSeeds.push_back(CDNSSeedData("198.11.174.140", "198.11.174.140"));



        base58Prefixes[PUBKEY_ADDRESS] = list_of(65);
        base58Prefixes[SCRIPT_ADDRESS] = list_of(28);
        base58Prefixes[SECRET_KEY] =     list_of(239);
        base58Prefixes[EXT_PUBLIC_KEY] = list_of(0x04)(0x88)(0xB2)(0x1E);
        base58Prefixes[EXT_SECRET_KEY] = list_of(0x04)(0x88)(0xAD)(0xE4);

        convertSeed6(vFixedSeeds, pnSeed6_main, ARRAYLEN(pnSeed6_main));

        nLastPOWBlock = 20000;
    }

    virtual const CBlock& GenesisBlock() const { return genesis; }
    virtual Network NetworkID() const { return CChainParams::MAIN; }

    virtual const vector<CAddress>& FixedSeeds() const {
        return vFixedSeeds;
    }
protected:
    CBlock genesis;
    vector<CAddress> vFixedSeeds;
};
static CMainParams mainParams;


//
// Testnet
//

class CTestNetParams : public CMainParams {
public:
    CTestNetParams() {
        // The message start string is designed to be unlikely to occur in normal data.
        // The characters are rarely used upper ASCII, not valid as UTF-8, and produce
        // a large 4-byte int at any alignment.
        pchMessageStart[0] = 0x3b;
        pchMessageStart[1] = 0x1c;
        pchMessageStart[2] = 0x34;
        pchMessageStart[3] = 0x41;
        bnProofOfWorkLimit = CBigNum(~uint256(0) >> 16);
        vAlertPubKey = ParseHex("");
        nDefaultPort = 30134;
        nRPCPort = 30135;
        strDataDir = "testnet";

        // Modify the testnet genesis block so the timestamp is valid for a later start.
        genesis.nBits  = bnProofOfWorkLimit.GetCompact();
        genesis.nNonce = 36893;
/*        
         if (true && genesis.GetHash() != hashGenesisBlock)
                         {
                             printf("Searching for genesis block...\n");
                             uint256 hashTarget = CBigNum().SetCompact(genesis.nBits).getuint256();
                             uint256 thash;

                             while (true)
                             {
                                 thash = genesis.GetHash();
                                 if (thash <= hashTarget)
                                     break;
                                 if ((genesis.nNonce & 0xFFF) == 0)
                                 {
                                     printf("nonce %08X: hash = %s (target = %s)\n", genesis.nNonce, thash.ToString().c_str(), hashTarget.ToString().c_str());
                                 }
                                 ++genesis.nNonce;
                                 if (genesis.nNonce == 0)
                                 {
                                     printf("NONCE WRAPPED, incrementing time\n");
                                     ++genesis.nTime;
                                }
                             }
                             printf("genesis.nTime = %u \n", genesis.nTime);
                             printf("genesis.nNonce = %u \n", genesis.nNonce);
                             printf("genesis.nVersion = %u \n", genesis.nVersion);
                             printf("genesis.hashMerkleRoot = %s \n", genesis.hashMerkleRoot.ToString().c_str()); //idk
                             printf("genesis.GetHash = %s\n", genesis.GetHash().ToString().c_str());

                         }

*/

        hashGenesisBlock = genesis.GetHash();
        assert(hashGenesisBlock == uint256("0x0000bc026d0a164c506186d8b677f92915b9884413a95e5191f8502e53af5b4a")); 
        vFixedSeeds.clear();
        vSeeds.clear();

        base58Prefixes[PUBKEY_ADDRESS] = list_of(111);
        base58Prefixes[SCRIPT_ADDRESS] = list_of(196);
        base58Prefixes[SECRET_KEY]     = list_of(239);
        base58Prefixes[EXT_PUBLIC_KEY] = list_of(0x04)(0x35)(0x87)(0xCF);
        base58Prefixes[EXT_SECRET_KEY] = list_of(0x04)(0x35)(0x83)(0x94);

        convertSeed6(vFixedSeeds, pnSeed6_test, ARRAYLEN(pnSeed6_test));

        nLastPOWBlock = 0x7fffffff;
    }
    virtual Network NetworkID() const { return CChainParams::TESTNET; }
};
static CTestNetParams testNetParams;


//
// Regression test
//
class CRegTestParams : public CTestNetParams {
public:
    CRegTestParams() {
        pchMessageStart[0] = 0xca;
        pchMessageStart[1] = 0xaf;
        pchMessageStart[2] = 0xc5;
        pchMessageStart[3] = 0xf8;
        bnProofOfWorkLimit = CBigNum(~uint256(0) >> 1);
        genesis.nTime = 1453581660;
        genesis.nBits  = bnProofOfWorkLimit.GetCompact();
        genesis.nNonce = 1;
        hashGenesisBlock = genesis.GetHash();
        nDefaultPort = 31135;
        strDataDir = "regtest";

/*

         if (true)
                         {
                             printf("Searching for genesis block...\n");
                             uint256 hashTarget = CBigNum().SetCompact(genesis.nBits).getuint256();
                             uint256 thash;

                             while (true)
                             {
                                 thash = genesis.GetHash();
                                 if (thash <= hashTarget)
                                     break;
                                 if ((genesis.nNonce & 0xFFF) == 0)
                                 {
                                     printf("nonce %08X: hash = %s (target = %s)\n", genesis.nNonce, thash.ToString().c_str(), hashTarget.ToString().c_str());
                                 }
                                 ++genesis.nNonce;
                                 if (genesis.nNonce == 0)
                                 {
                                     printf("NONCE WRAPPED, incrementing time\n");
                                     ++genesis.nTime;
                                 }
                             }
                             printf("genesis.nTime = %u \n", genesis.nTime);
                             printf("genesis.nNonce = %u \n", genesis.nNonce);
                             printf("genesis.nVersion = %u \n", genesis.nVersion);
                             printf("genesis.hashMerkleRoot = %s \n", genesis.hashMerkleRoot.ToString().c_str()); //idk
                             printf("genesis.GetHash = %s\n", genesis.GetHash().ToString().c_str());

                         }

*/
        assert(hashGenesisBlock == uint256("0x3ac31f9060f65c8d52ea61a90931df2e5368e2c52fad333bed1e5369992073db"));

        vSeeds.clear();  // Regtest mode doesn't have any DNS seeds.
    }

    virtual bool RequireRPCPassword() const { return false; }
    virtual Network NetworkID() const { return CChainParams::REGTEST; }
};
static CRegTestParams regTestParams;

static CChainParams *pCurrentParams = &mainParams;

const CChainParams &Params() {
    return *pCurrentParams;
}

void SelectParams(CChainParams::Network network) {
    switch (network) {
        case CChainParams::MAIN:
            pCurrentParams = &mainParams;
            break;
        case CChainParams::TESTNET:
            pCurrentParams = &testNetParams;
            break;
        case CChainParams::REGTEST:
            pCurrentParams = &regTestParams;
            break;
        default:
            assert(false && "Unimplemented network");
            return;
    }
}

bool SelectParamsFromCommandLine() {
    bool fRegTest = GetBoolArg("-regtest", false);
    bool fTestNet = GetBoolArg("-testnet", false);

    if (fTestNet && fRegTest) {
        return false;
    }

    if (fRegTest) {
        SelectParams(CChainParams::REGTEST);
    } else if (fTestNet) {
        SelectParams(CChainParams::TESTNET);
    } else {
        SelectParams(CChainParams::MAIN);
    }
    return true;
}
