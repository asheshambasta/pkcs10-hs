{-# LANGUAGE DeriveDataTypeable #-}
{-# LANGUAGE ExistentialQuantification #-}
{-# LANGUAGE PackageImports #-}
{-# LANGUAGE StandaloneDeriving #-}

{- |
Module      : Data.X509.PKCS10
License     : Apache-2.0
Maintainer  : Timothy Klim <hackage@timothyklim.com>
Stability   : experimental
Portability : unknown

Read/Write PKCS10 certificate signing request (also CSR or certification request).

Follows RFC2986
-}
module Data.X509.PKCS10 (
    X520Attribute (..),
    X520Attributes (..),
    PKCS9Attribute (..),
    PKCS9Attributes (..),
    CertificationRequestInfo (..),
    CertificationRequest (..),
    SignedCertificationRequest (..),
    Version (..),
    Signature (..),
    KeyPair (..),
    makeX520Attributes,
    generateCSR,
    csrToSigned,
    verify,
    encodeToDER,
    fromDER,
    toPEM,
    toNewFormatPEM,
    fromPEM,
) where

import Crypto.Hash
import Crypto.Number.Serialize
import Crypto.Random (MonadRandom)
import Data.ASN1.BinaryEncoding
import Data.ASN1.BitArray
import Data.ASN1.Encoding
import Data.ASN1.OID
import Data.ASN1.Parse
import qualified Data.ASN1.Types as ASN1
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as BC
import Data.PEM
import Data.Typeable
import qualified "crypton" Crypto.PubKey.DSA as DSA
import qualified "crypton" Crypto.PubKey.ECC.ECDSA as ECC
import qualified "crypton" Crypto.PubKey.ECC.Types as ECC
import qualified "crypton" Crypto.PubKey.RSA as RSA
import qualified "crypton" Crypto.PubKey.RSA.PKCS15 as RSA
import "crypton-x509" Data.X509

-- | A list of X520 attributes.
data X520Attribute
    = X520CommonName
    | X520SerialNumber
    | X520Name
    | X520Surname
    | X520GivenName
    | X520Initials
    | X520GenerationQualifier
    | X520CountryName
    | X520LocalityName
    | X520StateOrProvinceName
    | X520StreetAddress
    | X520OrganizationName
    | X520OrganizationalUnitName
    | X520Title
    | X520DNQualifier
    | X520Pseudonym
    | X509SubjectAltName
    | EmailAddress
    | IPAddress
    | DomainComponent
    | UserId
    | RawAttribute [Integer]
    deriving (Show, Eq)

instance ASN1.OIDable X520Attribute where
    getObjectID X520CommonName = [2, 5, 4, 3]
    getObjectID X520SerialNumber = [2, 5, 4, 5]
    getObjectID X520Name = [2, 5, 4, 41]
    getObjectID X520Surname = [2, 5, 4, 4]
    getObjectID X520GivenName = [2, 5, 4, 42]
    getObjectID X520Initials = [2, 5, 4, 43]
    getObjectID X520GenerationQualifier = [2, 5, 4, 44]
    getObjectID X520CountryName = [2, 5, 4, 6]
    getObjectID X520LocalityName = [2, 5, 4, 7]
    getObjectID X520StateOrProvinceName = [2, 5, 4, 8]
    getObjectID X520StreetAddress = [2, 5, 4, 9]
    getObjectID X520OrganizationName = [2, 5, 4, 10]
    getObjectID X520OrganizationalUnitName = [2, 5, 4, 11]
    getObjectID X520Title = [2, 5, 4, 12]
    getObjectID X520DNQualifier = [2, 5, 4, 46]
    getObjectID X520Pseudonym = [2, 5, 4, 65]
    getObjectID X509SubjectAltName = [2, 5, 29, 17]
    getObjectID EmailAddress = [1, 2, 840, 113549, 1, 9, 1]
    getObjectID IPAddress = [1, 3, 6, 1, 4, 1, 42, 2, 11, 2, 1]
    getObjectID DomainComponent = [0, 9, 2342, 19200300, 100, 1, 25]
    getObjectID UserId = [0, 9, 2342, 19200300, 100, 1, 1]
    getObjectID (RawAttribute oid) = oid

instance ASN1.OIDNameable X520Attribute where
    fromObjectID [2, 5, 4, 3] = Just X520CommonName
    fromObjectID [2, 5, 4, 5] = Just X520SerialNumber
    fromObjectID [2, 5, 4, 41] = Just X520Name
    fromObjectID [2, 5, 4, 4] = Just X520Surname
    fromObjectID [2, 5, 4, 42] = Just X520GivenName
    fromObjectID [2, 5, 4, 43] = Just X520Initials
    fromObjectID [2, 5, 4, 44] = Just X520GenerationQualifier
    fromObjectID [2, 5, 4, 6] = Just X520CountryName
    fromObjectID [2, 5, 4, 7] = Just X520LocalityName
    fromObjectID [2, 5, 4, 8] = Just X520StateOrProvinceName
    fromObjectID [2, 5, 4, 9] = Just X520StreetAddress
    fromObjectID [2, 5, 4, 10] = Just X520OrganizationName
    fromObjectID [2, 5, 4, 11] = Just X520OrganizationalUnitName
    fromObjectID [2, 5, 4, 12] = Just X520Title
    fromObjectID [2, 5, 4, 46] = Just X520DNQualifier
    fromObjectID [2, 5, 4, 65] = Just X520Pseudonym
    fromObjectID [2, 5, 29, 17] = Just X509SubjectAltName
    fromObjectID [1, 2, 840, 113549, 1, 9, 1] = Just EmailAddress
    fromObjectID [1, 3, 6, 1, 4, 1, 42, 2, 11, 2, 1] = Just IPAddress
    fromObjectID [0, 9, 2342, 19200300, 100, 1, 25] = Just DomainComponent
    fromObjectID [0, 9, 2342, 19200300, 100, 1, 1] = Just UserId
    fromObjectID oid = Just $ RawAttribute oid

-- | A list of PKCS9 extension attributes.
data PKCS9Attribute
    = forall e. (Extension e, Show e, Eq e, Typeable e) => PKCS9Attribute e

-- | PKCS9 extension attributes.
newtype PKCS9Attributes
    = PKCS9Attributes [PKCS9Attribute]
    deriving (Show, Eq)

instance Show PKCS9Attribute where
    show (PKCS9Attribute e) = show e

deriving instance Typeable ExtKeyUsage
deriving instance Typeable ExtSubjectKeyId
deriving instance Typeable ExtSubjectAltName
deriving instance Typeable ExtBasicConstraints
deriving instance Typeable ExtCrlDistributionPoints
deriving instance Typeable ExtAuthorityKeyId
deriving instance Typeable ExtExtendedKeyUsage

instance Eq PKCS9Attribute where
    (PKCS9Attribute x) == (PKCS9Attribute y) =
        case cast y of
            Just y' -> x == y'
            Nothing -> False

-- | X520 attributes.
newtype X520Attributes
    = X520Attributes [(X520Attribute, ASN1.ASN1CharacterString)]
    deriving (Show, Eq)

-- | CSR class.
data CertificationRequest = CertificationRequest
    { certificationRequestInfo :: CertificationRequestInfo
    , signatureAlgorithm :: SignatureALG
    , signature :: Signature
    }
    deriving (Show, Eq)

-- | A signed CSR class.
data SignedCertificationRequest = SignedCertificationRequest
    { certificationRequest :: CertificationRequest
    , rawCertificationRequestInfo :: B.ByteString -- raw bytes for verifying signature
    }
    deriving (Show, Eq)

-- | Certificate request info.
data CertificationRequestInfo = CertificationRequestInfo
    { version :: Version
    , subject :: X520Attributes
    , subjectPublicKeyInfo :: PubKey
    , attributes :: PKCS9Attributes
    }
    deriving (Show, Eq)

-- | Version of CSR (default 0).
newtype Version = Version Int deriving (Show, Eq)

-- | Signature of certificate request info.
newtype Signature
    = Signature B.ByteString
    deriving (Show, Eq)

-- | Errors.
data Error
    = ASN1UnknownError String
    | PEMUnknownFormat
    deriving (Show, Eq)

instance ASN1.ASN1Object CertificationRequest where
    toASN1 (CertificationRequest info sigAlg sig) xs =
        ASN1.Start ASN1.Sequence
            : ( ASN1.toASN1 info
                    . ASN1.toASN1 sigAlg
                    . ASN1.toASN1 sig
              )
                (ASN1.End ASN1.Sequence : xs)

    fromASN1 xs =
        f <$> (parseSignedCertificationRequest xs)
      where
        f (scr, xs') = (certificationRequest scr, xs')

parseSignedCertificationRequest :: [ASN1.ASN1] -> Either String (SignedCertificationRequest, [ASN1.ASN1])
parseSignedCertificationRequest (ASN1.Start ASN1.Sequence : xs) =
    f $ parseCertReqInfo xs
  where
    parseCertReqInfo xs' =
        case ASN1.fromASN1 xs' of
            Right (cri@CertificationRequestInfo{}, rest) ->
                runParseASN1State (p cri raw) rest
              where
                raw = encodeASN1' DER $ take (length xs' - length rest) xs'
            Left e -> Left e
    p cri raw =
        (flip SignedCertificationRequest raw)
            <$> (CertificationRequest cri <$> getObject <*> getObject)
    f (Right (req, ASN1.End ASN1.Sequence : xs')) =
        Right (req, xs')
    f (Right _) = Left "fromASN1: PKCS9.CertificationRequest: unknown format"
    f (Left e) = Left e
parseSignedCertificationRequest _ =
    Left "fromASN1: PKCS9.CertificationRequest: unknown format"

instance ASN1.ASN1Object Signature where
    toASN1 (Signature bs) xs =
        (ASN1.BitString $ toBitArray bs 0) : xs

    fromASN1 (ASN1.BitString s : xs) =
        Right (Signature $ bitArrayGetData s, xs)
    fromASN1 _ = Left "fromASN1: PKCS9.Signature: unknown format"

instance ASN1.ASN1Object CertificationRequestInfo where
    toASN1 (CertificationRequestInfo version subject pubKey attributes) xs =
        ASN1.Start ASN1.Sequence
            : ( ASN1.toASN1 version
                    . ASN1.toASN1 subject
                    . ASN1.toASN1 pubKey
                    . ASN1.toASN1 attributes
              )
                (ASN1.End ASN1.Sequence : xs)

    fromASN1 (ASN1.Start ASN1.Sequence : xs) =
        f $ runParseASN1State p xs
      where
        p =
            CertificationRequestInfo
                <$> getObject
                <*> getObject
                <*> getObject
                <*> getObject
        f (Right (req, ASN1.End ASN1.Sequence : xs)) = Right (req, xs)
        f (Right _) = Left "fromASN1: PKCS9.CertificationRequestInfo: unknown format"
        f (Left e) = Left e
    fromASN1 _ = Left "fromASN1: PKCS9.CertificationRequestInfo: unknown format"

instance ASN1.ASN1Object Version where
    toASN1 (Version v) xs =
        (ASN1.IntVal $ fromIntegral v) : xs

    fromASN1 (ASN1.IntVal n : xs) =
        Right (Version $ fromIntegral n, xs)
    fromASN1 _ = Left "fromASN1: PKCS9.Version: unknown format"

instance ASN1.ASN1Object X520Attributes where
    toASN1 (X520Attributes attrs) xs =
        ASN1.Start ASN1.Sequence
            : attrSet
            ++ ASN1.End ASN1.Sequence
            : xs
      where
        attrSet = concatMap f attrs
        f (attr, s) = [ASN1.Start ASN1.Set, ASN1.Start ASN1.Sequence, oid attr, cs s, ASN1.End ASN1.Sequence, ASN1.End ASN1.Set]
        oid attr = ASN1.OID $ getObjectID attr
        cs s = ASN1.ASN1String s

    fromASN1 (ASN1.Start ASN1.Sequence : xs) =
        f (X520Attributes []) xs
      where
        f
            (X520Attributes attrs)
            ( ASN1.Start ASN1.Set
                    : ASN1.Start ASN1.Sequence
                    : (ASN1.OID oid)
                    : (ASN1.ASN1String cs)
                    : ASN1.End ASN1.Sequence
                    : ASN1.End ASN1.Set
                    : rest
                ) =
                case fromObjectID oid of
                    Just attr -> f (X520Attributes $ (attr, cs) : attrs) rest
                    _ -> Left ("fromASN1: X520.Attributes: unknown oid" ++ show oid)
        f (X520Attributes attrs) (ASN1.End ASN1.Sequence : rest) =
            Right (X520Attributes $ reverse attrs, rest)
        f _ _ = Left "fromASN1: X520.Attributes: unknown format"
    fromASN1 _ = Left "fromASN1: X520.Attributes: unknown format"

instance ASN1.ASN1Object PKCS9Attribute where
    toASN1 (PKCS9Attribute attr) xs =
        ASN1.Start ASN1.Sequence : oid : os : ASN1.End ASN1.Sequence : xs
      where
        oid = ASN1.OID $ extOID attr
        os = (ASN1.OctetString . encodeASN1' DER . extEncode) attr

    fromASN1 (ASN1.Start ASN1.Sequence : ASN1.OID oid : ASN1.OctetString os : ASN1.End ASN1.Sequence : xs) =
        case oid of
            [2, 5, 29, 14] -> f (decode :: Either String ExtSubjectKeyId)
            [2, 5, 29, 15] -> f (decode :: Either String ExtKeyUsage)
            [2, 5, 29, 17] -> f (decode :: Either String ExtSubjectAltName)
            [2, 5, 29, 19] -> f (decode :: Either String ExtBasicConstraints)
            [2, 5, 29, 31] -> f (decode :: Either String ExtCrlDistributionPoints)
            [2, 5, 29, 35] -> f (decode :: Either String ExtAuthorityKeyId)
            [2, 5, 29, 37] -> f (decode :: Either String ExtExtendedKeyUsage)
            _ -> Left "fromASN1: PKCS9.Attribute: unknown oid"
      where
        decode :: forall e. (Extension e, Show e, Eq e, Typeable e) => Either String e
        decode = extDecode =<< decodeDER os
        f :: forall a. (Extension a, Show a, Eq a, Typeable a) => Either String a -> Either String (PKCS9Attribute, [ASN1.ASN1])
        f (Right attr) = Right (PKCS9Attribute attr, xs)
        f (Left e) = Left e
    fromASN1 _ = Left "fromASN1: PKCS9.Attribute: unknown format"

extensionRequestOid :: [Integer]
extensionRequestOid = [1, 2, 840, 113549, 1, 9, 14]

instance ASN1.ASN1Object PKCS9Attributes where
    toASN1 (PKCS9Attributes exts) xs =
        ASN1.Start (ASN1.Container ASN1.Context 0)
            : ctx
            ++ ASN1.End (ASN1.Container ASN1.Context 0)
            : xs
      where
        ctx = case exts of
            [] -> []
            es ->
                [ASN1.Start ASN1.Sequence, extOid, ASN1.Start ASN1.Set, ASN1.Start ASN1.Sequence]
                    ++ extSet
                    ++ [ASN1.End ASN1.Sequence, ASN1.End ASN1.Set, ASN1.End ASN1.Sequence]
              where
                extOid = ASN1.OID extensionRequestOid
                extSet = concatMap (flip ASN1.toASN1 []) es

    fromASN1 (ASN1.Start (ASN1.Container ASN1.Context 0) : xs) =
        f xs
      where
        f
            ( ASN1.Start ASN1.Sequence
                    : (ASN1.OID extOid)
                    : ASN1.Start ASN1.Set
                    : ASN1.Start ASN1.Sequence
                    : rest
                )
                | extOid == extensionRequestOid =
                    g [] rest
              where
                g
                    exts
                    ( ASN1.End ASN1.Sequence
                            : ASN1.End ASN1.Set
                            : ASN1.End ASN1.Sequence
                            : ASN1.End (ASN1.Container ASN1.Context 0)
                            : rest'
                        ) =
                        Right (PKCS9Attributes $ reverse exts, rest')
                g exts (rest'@(ASN1.Start ASN1.Sequence : _)) =
                    case ASN1.fromASN1 rest' of
                        Right (attr, xss) -> g (attr : exts) xss
                        Left e -> Left e
                g _ _ = Left "fromASN1: PKCS9.Attribute: unknown format"
        f (ASN1.End (ASN1.Container ASN1.Context 0) : rest') = Right (PKCS9Attributes [], rest')
        f _ = Left "fromASN1: PKCS9.Attributes: unknown format"
    fromASN1 _ = Left "fromASN1: PKCS9.Attributes: unknown format"

class (RSA.HashAlgorithmASN1 a) => HashAlgorithmConversion a where
    fromHashAlgorithmASN1 :: a -> HashALG

instance HashAlgorithmConversion MD2 where
    fromHashAlgorithmASN1 MD2 = HashMD2

instance HashAlgorithmConversion MD5 where
    fromHashAlgorithmASN1 MD5 = HashMD5

instance HashAlgorithmConversion SHA1 where
    fromHashAlgorithmASN1 SHA1 = HashSHA1

instance HashAlgorithmConversion SHA224 where
    fromHashAlgorithmASN1 SHA224 = HashSHA224

instance HashAlgorithmConversion SHA256 where
    fromHashAlgorithmASN1 SHA256 = HashSHA256

instance HashAlgorithmConversion SHA384 where
    fromHashAlgorithmASN1 SHA384 = HashSHA384

instance HashAlgorithmConversion SHA512 where
    fromHashAlgorithmASN1 SHA512 = HashSHA512

-- | Helper to convert string values as utf8 asn1 strings.
makeX520Attributes :: [(X520Attribute, String)] -> X520Attributes
makeX520Attributes xs =
    X520Attributes $ fmap f xs
  where
    f (attr, s) = (attr, ASN1.asn1CharacterString ASN1.UTF8 s)

encodeToDER :: (ASN1.ASN1Object o) => o -> BC.ByteString
encodeToDER = encodeASN1' DER . flip ASN1.toASN1 []

decodeDER :: BC.ByteString -> Either String [ASN1.ASN1]
decodeDER = either (Left . show) Right . decodeASN1' DER

decodeFromDER :: (ASN1.ASN1Object o) => BC.ByteString -> Either String (o, [ASN1.ASN1])
decodeFromDER bs = ASN1.fromASN1 =<< decodeDER bs

-- | Key pair for RSA, DSA and ECDSA keys.
data KeyPair
    = KeyPairRSA RSA.PublicKey RSA.PrivateKey
    | KeyPairDSA DSA.PublicKey DSA.PrivateKey
    | KeyPairECC ECC.PublicKey ECC.PrivateKey ECC.CurveName
    deriving (Show, Eq)

makeCertReqInfo :: X520Attributes -> PKCS9Attributes -> PubKey -> CertificationRequestInfo
makeCertReqInfo subject extAttrs pubKey =
    CertificationRequestInfo
        { version = Version 0
        , subject = subject
        , subjectPublicKeyInfo = pubKey
        , attributes = extAttrs
        }

makeCertReq :: (HashAlgorithmConversion hashAlg) => CertificationRequestInfo -> BC.ByteString -> hashAlg -> PubKeyALG -> CertificationRequest
makeCertReq certReq sig hashAlg pubKeyAlg =
    CertificationRequest
        { certificationRequestInfo = certReq
        , signatureAlgorithm = SignatureALG (fromHashAlgorithmASN1 hashAlg) pubKeyAlg
        , signature = Signature sig
        }

instance ASN1.ASN1Object DSA.Signature where
    toASN1 DSA.Signature{DSA.sign_r = r, DSA.sign_s = s} xs =
        ASN1.Start ASN1.Sequence : ASN1.IntVal r : ASN1.IntVal s : ASN1.End ASN1.Sequence : xs

    fromASN1 (ASN1.Start ASN1.Sequence : ASN1.IntVal r : ASN1.IntVal s : ASN1.End ASN1.Sequence : xs) =
        Right (DSA.Signature{DSA.sign_r = r, DSA.sign_s = s}, xs)
    fromASN1 _ = Left "fromASN1: DSA.Signature: unknown format"

instance ASN1.ASN1Object ECC.Signature where
    toASN1 ECC.Signature{ECC.sign_r = r, ECC.sign_s = s} xs =
        ASN1.Start ASN1.Sequence : ASN1.IntVal r : ASN1.IntVal s : ASN1.End ASN1.Sequence : xs

    fromASN1 (ASN1.Start ASN1.Sequence : ASN1.IntVal r : ASN1.IntVal s : ASN1.End ASN1.Sequence : xs) =
        Right (ECC.Signature{ECC.sign_r = r, ECC.sign_s = s}, xs)
    fromASN1 _ = Left "fromASN1: ECC.Signature: unknown format"

-- | Generate CSR.
generateCSR :: (MonadRandom m, HashAlgorithmConversion hashAlg, HashAlgorithm hashAlg) => X520Attributes -> PKCS9Attributes -> KeyPair -> hashAlg -> m (Either Error CertificationRequest)
generateCSR subject extAttrs (KeyPairRSA pubKey privKey) hashAlg =
    f <$> sign certReqInfo
  where
    certReqInfo = makeCertReqInfo subject extAttrs $ PubKeyRSA pubKey
    sign = RSA.signSafer (Just hashAlg) privKey . encodeToDER
    f = either (Left . ASN1UnknownError . show) (Right . certReq)
    certReq s = makeCertReq certReqInfo s hashAlg PubKeyALG_RSA
generateCSR subject extAttrs (KeyPairDSA pubKey privKey) hashAlg =
    f <$> sign certReqInfo
  where
    certReqInfo = makeCertReqInfo subject extAttrs $ PubKeyDSA pubKey
    sign = DSA.sign privKey hashAlg . encodeToDER
    f = Right . certReq . encodeToDER
    certReq s = makeCertReq certReqInfo s hashAlg PubKeyALG_DSA
generateCSR subject extAttrs (KeyPairECC pubKey privKey curveName) hashAlg =
    f <$> sign certReqInfo
  where
    certReqInfo = makeCertReqInfo subject extAttrs $ pubKeyECC pubKey curveName
    sign = ECC.sign privKey hashAlg . encodeToDER
    f = Right . certReq . encodeToDER
    certReq s = makeCertReq certReqInfo s hashAlg PubKeyALG_EC

-- | Sign CSR.
csrToSigned :: CertificationRequest -> SignedCertificationRequest
csrToSigned req =
    SignedCertificationRequest
        { certificationRequest = req
        , rawCertificationRequestInfo = encodeToDER . certificationRequestInfo $ req
        }

-- | Verify signed CSR.
verify :: SignedCertificationRequest -> Bool
verify csr
    | PubKeyRSA rsaPubKey <- pubKey
    , PubKeyALG_RSA <- sigAlg =
        rsaVerify hashAlg rsaPubKey raw sig
    | PubKeyDSA dsaPubKey <- pubKey
    , PubKeyALG_DSA <- sigAlg
    , Just dsaSig <- getDSASig sig
    , HashSHA1 <- hashAlg =
        DSA.verify SHA1 dsaPubKey dsaSig raw
    | otherwise = False
  where
    raw = rawCertificationRequestInfo csr :: BC.ByteString

    csr' = certificationRequest csr
    SignatureALG hashAlg sigAlg = signatureAlgorithm csr'
    Signature sig = signature csr'
    pubKey = subjectPublicKeyInfo $ certificationRequestInfo csr' :: PubKey

    -- \| Helpers:

    rsaVerify :: HashALG -> RSA.PublicKey -> BC.ByteString -> BC.ByteString -> Bool
    rsaVerify HashMD2 = RSA.verify (Just MD2)
    rsaVerify HashMD5 = RSA.verify (Just MD5)
    rsaVerify HashSHA1 = RSA.verify (Just SHA1)
    rsaVerify HashSHA224 = RSA.verify (Just SHA224)
    rsaVerify HashSHA256 = RSA.verify (Just SHA256)
    rsaVerify HashSHA384 = RSA.verify (Just SHA384)
    rsaVerify HashSHA512 = RSA.verify (Just SHA512)

    getDSASig :: BC.ByteString -> Maybe DSA.Signature
    getDSASig bs = case decodeFromDER bs of
        Right (dsaSig, _) -> Just dsaSig
        _ -> Nothing

requestHeader :: String
requestHeader = "CERTIFICATE REQUEST"

-- | Convert CSR to PEM format.
toPEM :: CertificationRequest -> PEM
toPEM req =
    PEM
        { pemName = requestHeader
        , pemHeader = []
        , pemContent = encodeToDER req
        }

newFormatRequestHeader :: String
newFormatRequestHeader = "NEW CERTIFICATE REQUEST"

-- | Convert CSR to PEM new format.
toNewFormatPEM :: CertificationRequest -> PEM
toNewFormatPEM req =
    PEM
        { pemName = newFormatRequestHeader
        , pemHeader = []
        , pemContent = encodeToDER req
        }

-- | Convert ByteString to signed CSR.
fromDER :: BC.ByteString -> Either Error SignedCertificationRequest
fromDER bs =
    fst <$> f (parseSignedCertificationRequest =<< decodeDER bs)
  where
    f = either (Left . ASN1UnknownError . show) Right

-- | Convert PEM to signed CSR.
fromPEM :: PEM -> Either Error SignedCertificationRequest
fromPEM p =
    if pemName p == requestHeader || pemName p == newFormatRequestHeader
        then fromDER . pemContent $ p
        else Left PEMUnknownFormat

{- | Need conversion since Public key definitions are different in cryptonite and X509
| Public point to Serilized point helper from
| https://github.com/vincenthz/hs-certificate/blob/f993eadf20072bf31f238c48eb76b2509a5a1c7d/x509-validation/Tests/Certificate.hs#L142
-}
pubKeyECC :: ECC.PublicKey -> ECC.CurveName -> PubKey
pubKeyECC pb curveName =
    PubKeyEC (PubKeyEC_Named curveName pub)
  where
    ECC.Point x y = ECC.public_q pb
    pub = SerializedPoint bs
    bs = B.cons 4 (i2ospOf_ bytes x `B.append` i2ospOf_ bytes y)
    bits = ECC.curveSizeBits (ECC.getCurveByName curveName)
    bytes = (bits + 7) `div` 8
