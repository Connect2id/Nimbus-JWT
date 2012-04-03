package com.nimbusds.jwt;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;

/**
 * 
 * @author Axel Nennker
 */
public class TestCertsAndKeys {

        static final String cert1B64 = 
	          "MIIDkDCCAvmgAwIBAgIJAO+Fcd4yj0h/MA0GCSqGSIb3DQEBBQUAMIGNMQswCQYD"
                + "VQQGEwJVUzETMBEGA1UECBMKQ2FsaWZvcm5pYTEWMBQGA1UEBxMNU2FuIEZyYW5j"
                + "aXNjbzEPMA0GA1UEChMGeG1sZGFwMScwJQYDVQQLFB5DaHVjayBNb3J0aW1vcmUg"
                + "JiBBeGVsIE5lbm5rZXIxFzAVBgNVBAMTDnd3dy54bWxkYXAub3JnMB4XDTA3MDgx"
                + "ODIxMTIzMVoXDTE3MDgxNTIxMTIzMVowgY0xCzAJBgNVBAYTAlVTMRMwEQYDVQQI"
                + "EwpDYWxpZm9ybmlhMRYwFAYDVQQHEw1TYW4gRnJhbmNpc2NvMQ8wDQYDVQQKEwZ4"
                + "bWxkYXAxJzAlBgNVBAsUHkNodWNrIE1vcnRpbW9yZSAmIEF4ZWwgTmVubmtlcjEX"
                + "MBUGA1UEAxMOd3d3LnhtbGRhcC5vcmcwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJ"
                + "AoGBAOKUn6/QqTZj/BWoQVxNFI0Z2AXI1azws+RyuJek60NiawQrFAKk0Ph+/YnU"
                + "iQAnzbsT+juZV08UpaPa2IE3g0+RFZtODlqoGGGakSOd9NNnDuNhsdtXJWgQq8pa"
                + "M9Sc4nUue31iq7LvmjSGSL5w84NglT48AcqVGr+/5vy8CfT/AgMBAAGjgfUwgfIw"
                + "HQYDVR0OBBYEFGcwQKLQtW8/Dql5t70BfXX66dmaMIHCBgNVHSMEgbowgbeAFGcw"
                + "QKLQtW8/Dql5t70BfXX66dmaoYGTpIGQMIGNMQswCQYDVQQGEwJVUzETMBEGA1UE"
                + "CBMKQ2FsaWZvcm5pYTEWMBQGA1UEBxMNU2FuIEZyYW5jaXNjbzEPMA0GA1UEChMG"
                + "eG1sZGFwMScwJQYDVQQLFB5DaHVjayBNb3J0aW1vcmUgJiBBeGVsIE5lbm5rZXIx"
                + "FzAVBgNVBAMTDnd3dy54bWxkYXAub3JnggkA74Vx3jKPSH8wDAYDVR0TBAUwAwEB"
                + "/zANBgkqhkiG9w0BAQUFAAOBgQAYQisGgrg1xw0TTgIZcz3JXr+ZtwjeKqEewoxC"
                + "xBz1uki7hJYHIznEZq4fzSMtcBMgbKmOTzFNV0Yr/tnJ9rrljRf8EXci62ffzj+K"
                + "kny7JtM6Ltxq0BJuF3jrXogdbsc5J3W9uJ7C2+uJTHG1mApbOdJGvLAGLCaNw5Np"
                + "P7+ZXQ==";

        /** Creates a new instance of XmldapCertsAndKeys */
        private TestCertsAndKeys() {
        
	}

        public static X509Certificate getXmldapCert() 
		throws CertificateException {
		
                String certB64 = "MIIDXTCCAkUCBEQd+4EwDQYJKoZIhvcNAQEEBQAwczELMAkGA1UEBhMCVVMxEzARBgNVBAgTCkNh"
                                + "bGlmb3JuaWExFjAUBgNVBAcTDVNhbiBGcmFuY2lzY28xDzANBgNVBAoTBnhtbGRhcDERMA8GA1UE"
                                + "CxMIaW5mb2NhcmQxEzARBgNVBAMTCnhtbGRhcC5vcmcwHhcNMDYwMzIwMDA0NjU3WhcNMDYwNjE4"
                                + "MDA0NjU3WjBzMQswCQYDVQQGEwJVUzETMBEGA1UECBMKQ2FsaWZvcm5pYTEWMBQGA1UEBxMNU2Fu"
                                + "IEZyYW5jaXNjbzEPMA0GA1UEChMGeG1sZGFwMREwDwYDVQQLEwhpbmZvY2FyZDETMBEGA1UEAxMK"
                                + "eG1sZGFwLm9yZzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANMnkVA4xfpG0bLos9FO"
                                + "pNBjHAdFahy2cJ7FUwuXd/IShnG+5qF/z1SdPWzRxTtpFFyodtXlBUEIbiT+IbYPZF1vCcBrcFa8"
                                + "Kz/4rBjrpPZgllgA/WSVKjnJvw8q4/tO6CQZSlRlj/ebNK9VyT1kN+MrKV1SGTqaIJ2l+7Rd05WH"
                                + "scwZMPdVWBbRrg76YTfy6H/NlQIArNLZanPvE0Vd5QfD4ZyG2hTh3y7ZlJAUndGJ/kfZw8sKuL9Q"
                                + "Srh4eOTc280NQUmPGz6LP5MXNmu0RxEcomod1+ToKll90yEKFAUKuPYFgm9J+vYm4tzRequLy/nj"
                                + "teRIkcfAdcAtt6PCYjUCAwEAATANBgkqhkiG9w0BAQQFAAOCAQEAURtxiA7qDSq/WlUpWpfWiZ7H"
                                + "vveQrwTaTwV/Fk3l/I9e9WIRN51uFLuiLtZMMwR02BX7Yva1KQ/Gl999cm/0b5hptJ+TU29rVPZI"
                                + "lI32c5vjcuSVoEda8+BRj547jlC0rNokyWm+YtBcDOwfHSPFFwVPPVxyQsVEebsiB6KazFq6iZ8A"
                                + "0F2HLEnpsdFnGrSwBBbH3I3PH65ofrTTgj1Mjk5kA6EVaeefDCtlkX2ogIFMlcS6ruihX2mlCLUS"
                                + "rlPs9TH+M4j/R/LV5QWJ93/X9gsxFrxVFGg3b75EKQP8MZ111/jaeKd80mUOAiTO06EtfjXZPrjP"
                                + "N4e2l05i2EGDUA==";
                byte[] certBytes = BASE64.decode(certB64);
                CertificateFactory cf = CertificateFactory.getInstance("X509");
                ByteArrayInputStream inStream = new ByteArrayInputStream(certBytes);
                return (X509Certificate) cf.generateCertificate(inStream);
        }

        public static RSAPrivateKey getXmldapPrivateKey()
		throws InvalidKeySpecException, NoSuchAlgorithmException {
                
		String exponentB64 = "AKh/FZVHiKxcIPA8g2mN8TUdMXuX58I7z4jS+57vYta387MG3DGZtQ/XXfHdPx9WjdoW0KWE2Pl5"
                                + "SbOZW7tVcwigF88FrSJ5i6XDwUktmXjFwJM/TvUZlxWAKUdoOX8MC3DrAYZxeT3kC1mzAiBMPdC4"
                                + "W4zNe7Zo0YgbsMzQZowVxZTP4GWa/L8o3adXTvdobP1nKW5buPj9vkgaGCTxE0vQzbuiGj1HRJe9"
                                + "MRtvcU/I2shiIVE0F35wk8gw0FATtkvMpTpR12YVeo1JGZsHFQoD7gTD/n/NmC9Rjk2baYGj97hV"
                                + "9EpDRcPNsMll2pVRy4Z45j2+t/yl8WjaqK5lhkE=";
                
		String modulusB64 = "ANMnkVA4xfpG0bLos9FOpNBjHAdFahy2cJ7FUwuXd/IShnG+5qF/z1SdPWzRxTtpFFyodtXlBUEI"
                                + "biT+IbYPZF1vCcBrcFa8Kz/4rBjrpPZgllgA/WSVKjnJvw8q4/tO6CQZSlRlj/ebNK9VyT1kN+Mr"
                                + "KV1SGTqaIJ2l+7Rd05WHscwZMPdVWBbRrg76YTfy6H/NlQIArNLZanPvE0Vd5QfD4ZyG2hTh3y7Z"
                                + "lJAUndGJ/kfZw8sKuL9QSrh4eOTc280NQUmPGz6LP5MXNmu0RxEcomod1+ToKll90yEKFAUKuPYF"
                                + "gm9J+vYm4tzRequLy/njteRIkcfAdcAtt6PCYjU=";
                
		byte[] exponentBytes = BASE64.decode(exponentB64);
                byte[] modulusBytes = BASE64.decode(modulusB64);
                BigInteger exponent = new BigInteger(1, exponentBytes);
                BigInteger modulus = new BigInteger(1, modulusBytes);
                RSAPrivateKeySpec ks = new RSAPrivateKeySpec(modulus, exponent);
                KeyFactory kf = KeyFactory.getInstance("RSA");
                return (RSAPrivateKey) kf.generatePrivate(ks);
        }

        public static String getXmldapCert1String() {
                return cert1B64;
        }

        public static X509Certificate getXmldapCert1() 
		throws CertificateException {
                
		byte[] certBytes = BASE64.decode(cert1B64);
                CertificateFactory cf = CertificateFactory.getInstance("X509");
                ByteArrayInputStream inStream = new ByteArrayInputStream(certBytes);
                return (X509Certificate) cf.generateCertificate(inStream);
        }

        public static RSAPrivateKey getXmldapPrivateKey1()
		throws InvalidKeySpecException, NoSuchAlgorithmException {
		
                byte[] modulusBytes = {    
                                (byte)0x00,(byte)0xe2,(byte)0x94,(byte)0x9f,(byte)0xaf,(byte)0xd0,(byte)0xa9,(byte)0x36,(byte)0x63,(byte)0xfc,(byte)0x15,(byte)0xa8,(byte)0x41,(byte)0x5c,(byte)0x4d,
                                (byte)0x14,(byte)0x8d,(byte)0x19,(byte)0xd8,(byte)0x05,(byte)0xc8,(byte)0xd5,(byte)0xac,(byte)0xf0,(byte)0xb3,(byte)0xe4,(byte)0x72,(byte)0xb8,(byte)0x97,(byte)0xa4,
                                (byte)0xeb,(byte)0x43,(byte)0x62,(byte)0x6b,(byte)0x04,(byte)0x2b,(byte)0x14,(byte)0x02,(byte)0xa4,(byte)0xd0,(byte)0xf8,(byte)0x7e,(byte)0xfd,(byte)0x89,(byte)0xd4,
                                (byte)0x89,(byte)0x00,(byte)0x27,(byte)0xcd,(byte)0xbb,(byte)0x13,(byte)0xfa,(byte)0x3b,(byte)0x99,(byte)0x57,(byte)0x4f,(byte)0x14,(byte)0xa5,(byte)0xa3,(byte)0xda,
                                (byte)0xd8,(byte)0x81,(byte)0x37,(byte)0x83,(byte)0x4f,(byte)0x91,(byte)0x15,(byte)0x9b,(byte)0x4e,(byte)0x0e,(byte)0x5a,(byte)0xa8,(byte)0x18,(byte)0x61,(byte)0x9a,
                                (byte)0x91,(byte)0x23,(byte)0x9d,(byte)0xf4,(byte)0xd3,(byte)0x67,(byte)0x0e,(byte)0xe3,(byte)0x61,(byte)0xb1,(byte)0xdb,(byte)0x57,(byte)0x25,(byte)0x68,(byte)0x10,
                                (byte)0xab,(byte)0xca,(byte)0x5a,(byte)0x33,(byte)0xd4,(byte)0x9c,(byte)0xe2,(byte)0x75,(byte)0x2e,(byte)0x7b,(byte)0x7d,(byte)0x62,(byte)0xab,(byte)0xb2,(byte)0xef,
                                (byte)0x9a,(byte)0x34,(byte)0x86,(byte)0x48,(byte)0xbe,(byte)0x70,(byte)0xf3,(byte)0x83,(byte)0x60,(byte)0x95,(byte)0x3e,(byte)0x3c,(byte)0x01,(byte)0xca,(byte)0x95,
                                (byte)0x1a,(byte)0xbf,(byte)0xbf,(byte)0xe6,(byte)0xfc,(byte)0xbc,(byte)0x09,(byte)0xf4,(byte)0xff};
                
		byte[] exponentBytes = {
                                (byte)0x1d,(byte)0xe6,(byte)0xf1,(byte)0x60,(byte)0x19,(byte)0x90,(byte)0x8b,(byte)0x4e,(byte)0x0c,(byte)0xb1,(byte)0xaa,(byte)0xff,(byte)0xdd,(byte)0x37,(byte)0x8a,
                                (byte)0xf3,(byte)0xc8,(byte)0x2a,(byte)0x5b,(byte)0x31,(byte)0x13,(byte)0x09,(byte)0xfc,(byte)0xc6,(byte)0x30,(byte)0xea,(byte)0xf6,(byte)0xf3,(byte)0x84,(byte)0x5f,
                                (byte)0x4c,(byte)0x08,(byte)0x4c,(byte)0x09,(byte)0x43,(byte)0xca,(byte)0x23,(byte)0x43,(byte)0x2f,(byte)0x14,(byte)0xec,(byte)0x65,(byte)0x77,(byte)0x70,(byte)0x26,
                                (byte)0x18,(byte)0x70,(byte)0x28,(byte)0x55,(byte)0x7d,(byte)0x20,(byte)0x74,(byte)0x07,(byte)0x1b,(byte)0x9f,(byte)0xa3,(byte)0x20,(byte)0xed,(byte)0x0b,(byte)0xef,
                                (byte)0xb0,(byte)0xb5,(byte)0xeb,(byte)0xcd,(byte)0x2f,(byte)0xcd,(byte)0x4d,(byte)0xde,(byte)0x37,(byte)0xe5,(byte)0x86,(byte)0x55,(byte)0xf2,(byte)0x34,(byte)0xe7,
                                (byte)0xd9,(byte)0xf7,(byte)0xb3,(byte)0x45,(byte)0x2a,(byte)0x92,(byte)0x1b,(byte)0x54,(byte)0x49,(byte)0x41,(byte)0x81,(byte)0xbd,(byte)0xc0,(byte)0x63,(byte)0xd1,
                                (byte)0x86,(byte)0x45,(byte)0xe7,(byte)0xe3,(byte)0xb3,(byte)0xf5,(byte)0x77,(byte)0x5f,(byte)0x46,(byte)0x93,(byte)0x20,(byte)0x19,(byte)0x9a,(byte)0x26,(byte)0x9f,
                                (byte)0x48,(byte)0x27,(byte)0x4b,(byte)0x93,(byte)0xa7,(byte)0x1c,(byte)0xf2,(byte)0x8a,(byte)0x3b,(byte)0xbe,(byte)0x40,(byte)0x85,(byte)0x92,(byte)0x8a,(byte)0x3c,
                                (byte)0xfd,(byte)0xeb,(byte)0x18,(byte)0x2e,(byte)0x04,(byte)0x69,(byte)0xe5,(byte)0xa1};
                
		BigInteger exponent = new BigInteger(1, exponentBytes);
                BigInteger modulus = new BigInteger(1, modulusBytes);
                
		RSAPrivateKeySpec ks = new RSAPrivateKeySpec(modulus, exponent);
                KeyFactory kf = KeyFactory.getInstance("RSA");
                return (RSAPrivateKey) kf.generatePrivate(ks);
        }
}
