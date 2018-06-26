/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.fabiel.certificationauthority;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.UnrecoverableEntryException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Vector;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.misc.MiscObjectIdentifiers;
import org.bouncycastle.asn1.misc.NetscapeCertType;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.SubjectDirectoryAttributes;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.jce.X509Principal;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.x509.AttributeCertificateHolder;
import org.bouncycastle.x509.AttributeCertificateIssuer;
import org.bouncycastle.x509.X509Attribute;
import org.bouncycastle.x509.X509V1CertificateGenerator;
import org.bouncycastle.x509.X509V2AttributeCertificate;
import org.bouncycastle.x509.X509V2AttributeCertificateGenerator;
import org.bouncycastle.x509.X509V3CertificateGenerator;
import org.bouncycastle.x509.extension.AuthorityKeyIdentifierStructure;
import org.bouncycastle.x509.extension.SubjectKeyIdentifierStructure;

/**
 *
 * @author Fabiel <fabiel.leon at gmail.com>
 */
public class CustomCertificationAuthority {

    static X509V1CertificateGenerator v1CertGen = new X509V1CertificateGenerator();
    static X509V3CertificateGenerator v3CertGen = new X509V3CertificateGenerator();

    public static X509Certificate createClientCert(
            PublicKey pubKey,
            PrivateKey caPrivKey,
            PublicKey caPubKey,
            Certificate caCertificate,
            String domain)
            throws Exception {
        //
        // issuer
        //
        String issuer = "C=CU,"
                + "ST=La Habana,"
                + "L=Playa,"
                + "O=Mi Casa,"
                + "OU=Direccion,"
                + "CN=Fabiel Leon";
//        String issuer = "CN=Fabiel Leon, OU=Direccion, O=Mi Casa, L=Playa, ST=La Habana, C=CU";
//        String issuer = "C=AU, O=The Legion of the Bouncy Castle, OU=Bouncy Primary Certificate";
        //
        // subjects name table.
        //
        Hashtable attrs = new Hashtable();
        Vector order = new Vector();

        attrs.put(X509Principal.C, "CU");
        attrs.put(X509Principal.O, "Mi Casa");
        attrs.put(X509Principal.L, "Playa");
        attrs.put(X509Principal.CN, domain);
//        attrs.put(X509Principal.ST, "La Habana");
        attrs.put(X509Principal.EmailAddress, "fleon90@nauta.cu");

        order.addElement(X509Principal.C);
        order.addElement(X509Principal.O);
        order.addElement(X509Principal.L);
        order.addElement(X509Principal.CN);
        order.addElement(X509Principal.EmailAddress);

        //
        // create the certificate - version 3
        //
        v3CertGen.reset();

        v3CertGen.setSerialNumber(BigInteger.valueOf(20));
        v3CertGen.setIssuerDN(new X509Principal(issuer));
//        v3CertGen.setIssuerDN(new X509Principal(issuer));
//        v3CertGen.setNotBefore(new Date(System.currentTimeMillis() - 1000L * 60 * 60 * 24 * 30));
        v3CertGen.setNotBefore(new Date(System.currentTimeMillis()));
        v3CertGen.setNotAfter(new Date(System.currentTimeMillis() + (1000L * 60 * 60 * 24 * 3650)));
        v3CertGen.setSubjectDN(new X509Principal(order, attrs));
        v3CertGen.setPublicKey(pubKey);
        v3CertGen.setSignatureAlgorithm("SHA1WithDSA");

        //
        // add the extensions
        //
        v3CertGen.addExtension(
                MiscObjectIdentifiers.netscapeCertType,
                false,
                new NetscapeCertType(NetscapeCertType.objectSigning | NetscapeCertType.smime
                //                |NetscapeCertType.sslCA 
                //                        | NetscapeCertType.objectSigningCA | NetscapeCertType.smimeCA
                ));
        //
        // add the extensions
        //
        v3CertGen.addExtension(
                X509Extensions.SubjectKeyIdentifier,
                false,
                new SubjectKeyIdentifierStructure(pubKey));
        v3CertGen.addExtension(
                X509Extensions.AuthorityKeyIdentifier,
                false,
                new AuthorityKeyIdentifierStructure(caPubKey));
//v3CertGen.addExtension(
//                X509Extensions.SubjectAlternativeName,
//                false,
//                new SubjectDirectoryAttributes(null));
        X509Certificate cert = v3CertGen.generate(caPrivKey);

        cert.checkValidity(new Date());

        cert.verify(caPubKey);

        return cert;
    }

    public static void genCertForSite(String domain) {
        //BouncyCastle
        Security.addProvider(new BouncyCastleProvider());
        try {
            String password = "123456";
            // load the keystore, supplying the store password
            KeyStore jks = KeyStore.getInstance("JKS");
            jks.load(new FileInputStream("../.keystore"), password.toCharArray());

// get the 'entry'
            KeyStore.ProtectionParameter protParam = new KeyStore.PasswordProtection(password.toCharArray());
            KeyStore.PrivateKeyEntry caPkEntry = (KeyStore.PrivateKeyEntry) jks.getEntry("fabiel ca", protParam);

// grab the bits from the private key
            PrivateKey caPrivateKey = caPkEntry.getPrivateKey();

            //certificate publico de CA
            X509Certificate caCert = (X509Certificate) caPkEntry.getCertificate();
//            byte[] encoded = caCertificate.getEncoded();
//            byte[] encoded1 = caCertificate.getPublicKey().getEncoded();
//            System.out.println("cert public key = " + DatatypeConverter.printHexBinary(encoded1));
//            System.out.println("enconded = " + DatatypeConverter.printHexBinary(encoded));
//            System.out.println("myPrivateKey = " + myPrivateKey);
//Now I could hand myPrivateKey (assuming it was the right sort of key, of course), to something like:

//firmar string
            // import java.security.*
//            Signature sig = Signature.getInstance("SHA1withDSA");
//            sig.initSign(myPrivateKey);
//            sig.update("asssssssssssssssssssssssss".getBytes());
//            byte[] sign = sig.sign();
//            String printHexBinary = javax.xml.bind.DatatypeConverter.printHexBinary(sign);
//            System.out.println("printHexBinary = " + printHexBinary);
            //
            // set up the keys
            //
//            KeyFactory fact = KeyFactory.getInstance("RSA", "BC");
//        PrivateKey          caPrivKey = fact.generatePrivate(caPrivKeySpec);
//        PublicKey           caPubKey = fact.generatePublic(caPubKeySpec);
            KeyPairGenerator instance = KeyPairGenerator.getInstance("RSA");
            KeyPair genKeyPair = instance.genKeyPair();
            PublicKey clientPublicKey = genKeyPair.getPublic();
            PrivateKey clientPrivateKey = genKeyPair.getPrivate();
//                String format = javax.xml.bind.DatatypeConverter.printBase64Binary(genKeyPair.getPrivate().getEncoded());
//                System.out.println("format = " + format);
//                String format1 = javax.xml.bind.DatatypeConverter.printBase64Binary(genKeyPair.getPublic().getEncoded());
//                System.out.println("format1 = " + format1);
//                String domain = "hello.com";
            X509Certificate clientCert = createClientCert(clientPublicKey, caPrivateKey, caCert.getPublicKey(), caCert, domain);

//<editor-fold defaultstate="collapsed" desc="garbage">
                /*                // Instantiate a new AC generator
             X509V2AttributeCertificateGenerator acGen = new X509V2AttributeCertificateGenerator();
                
             acGen.reset();
                
             //
             // Holder: here we use the IssuerSerial form
             //
             acGen.setHolder(new AttributeCertificateHolder(clientCert));
                
             // set the Issuer
             acGen.setIssuer(new AttributeCertificateIssuer(caCert.getSubjectX500Principal()));
                
             //
             // serial number (as it's an example we don't have to keep track of the
             // serials anyway
             //
             acGen.setSerialNumber(new BigInteger("1"));
                
             // not Before
             acGen.setNotBefore(new Date(System.currentTimeMillis() - 50000));
                
             // not After
             acGen.setNotAfter(new Date(System.currentTimeMillis() + 50000));
                
             // signature Algorithmus
             acGen.setSignatureAlgorithm("SHA1WithDSA");
                
             // the actual attributes
             GeneralName roleName = new GeneralName(GeneralName.rfc822Name, "DAU123456789");
             ASN1EncodableVector roleSyntax = new ASN1EncodableVector();
             roleSyntax.add(roleName);
                
             // roleSyntax OID: 2.5.24.72
             X509Attribute attributes = new X509Attribute("2.5.24.72",
             new DERSequence(roleSyntax));
                
             acGen.addAttribute(attributes);
                
             //      finally create the AC
             X509V2AttributeCertificate att = (X509V2AttributeCertificate) acGen
             .generate(caPrivateKey, "BC");
                
             AttributeCertificateHolder h = att.getHolder();
             if (h.match(clientCert)) {
             if (h.getEntityNames() != null) {
             System.out.println(h.getEntityNames().length + " entity names found");
             }
             if (h.getIssuer() != null) {
             System.out.println(h.getIssuer().length + " issuer names found, serial number " + h.getSerialNumber());
             }
             System.out.println("Matches original client x509 cert");
             }
                
             // Issuer
             AttributeCertificateIssuer issuer = att.getIssuer();
             if (issuer.match(caCert)) {
             if (issuer.getPrincipals() != null) {
             System.out.println(issuer.getPrincipals().length + " entity names found");
             }
             System.out.println("Matches original ca x509 cert");
             }
                
             // Dates
             System.out.println("valid not before: " + att.getNotBefore());
             System.out.println("valid not before: " + att.getNotAfter());*/
// check the dates, an exception is thrown in checkValidity()...
//                try {
//                    att.checkValidity();
//                    att.checkValidity(new Date());
//                } catch (Exception e) {
//                    System.out.println(e);
//                }
//</editor-fold>
//                createAcIssuerCert.
            X509Certificate[] chain = new X509Certificate[]{clientCert, caCert};
//            jks.deleteEntry("CAClientCert");
//            jks.deleteEntry("CAClientPrivateKey");
//            jks.deleteEntry("hello.com");
            jks.deleteEntry(domain);
//                jks.setCertificateEntry("CAClientCert", clientCert);
//            if (!"www.google.com".equals(domain)) {
            jks.setKeyEntry(domain, clientPrivateKey, password.toCharArray(), chain);
//            } else {
//                jks.setKeyEntry(domain, clientPrivateKey, domain.toCharArray(), chain);
//            }

//                CertificateEntry("CAClientCert", createAcIssuerCert);
//               
            jks.store(new FileOutputStream("../.keystore" + domain), password.toCharArray());
            System.out.println("*********************************");
            Enumeration<String> aliases = jks.aliases();
            while (aliases.hasMoreElements()) {
                String string = aliases.nextElement();
                System.out.println("string = " + string);
            }
            System.out.println("************************************");
//                createAcIssuerCert.

        } catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException | UnrecoverableEntryException ex) {
            Logger.getLogger(CustomCertificationAuthority.class.getName()).log(Level.SEVERE, null, ex);
        } catch (Exception ex) {
            Logger.getLogger(CustomCertificationAuthority.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    /**
     *
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        genCertForSite("www.google.com");
        genCertForSite("hello.com");
//            PrivateKey privKey = fact.generatePrivate();
//            PublicKey pubKey = fact.generatePublic(pubKeySpec);
//
//            try {
//                
//            } catch (Exception ex) {
//                Logger.getLogger(CustomCertificationAuthority.class.getName()).log(Level.SEVERE, null, ex);
//            }
//OBTENER CERT DE WINDOWS
//            KeyStore keyStore = KeyStore.getInstance("Windows-ROOT");
//            keyStore.load(null, null);
//            String alias = "MyAlias";
//
//            // Extract key associated with the specified alias
//            Key key = keyStore.getKey(alias, null);
//            Certificate cert = keyStore.getCertificate(alias);
//
//            if (key instanceof PrivateKey) {
//                // Do stuff ...
//            }
//IMPORTAR CERTIFICADOS DER y PEM
//            // read the key file from disk and create a PrivateKey
//            FileInputStream fis = new FileInputStream("pkey.der");
//            DataInputStream dis = new DataInputStream(fis);
//            byte[] bytes = new byte[dis.available()];
//            dis.readFully(bytes);
//            byte[] keyBytes;
//            KeyFactory kf;
//            try (ByteArrayInputStream bais = new ByteArrayInputStream(bytes)) {
//                keyBytes = new byte[bais.available()];
//                kf = KeyFactory.getInstance("RSA");
//                bais.read(keyBytes, 0, bais.available());
//            }
//            // read the certificates from the files and load them into the key store:
//            Collection certs = CertificateFactory.getInstance("X509").generateCertificates(new FileInputStream("cert1.pem"));
//            Certificate crt1 = (Certificate) certs.iterator().next();
//
//            Certificate[] chain = new Certificate[]{crt1};
//
//            String alias1 = ((X509Certificate) crt1).getSubjectX500Principal().getName();
//
//            jks.setCertificateEntry(alias1, crt1);
//
//// store the private key
//            String defaultalias = "importkey";
//            PKCS8EncodedKeySpec keysp = new PKCS8EncodedKeySpec(keyBytes);
//            PrivateKey ff = kf.generatePrivate(keysp);
//            jks.setKeyEntry(defaultalias, ff, password.toCharArray(), chain);
//
//// save the key store to a file         
//            jks.store(new FileOutputStream("mykeystore"), password.toCharArray());
    }

//
//    I'm not an expert in java's security packages but to my knowledge there is no straight forward way to create the keypair from public API.
//
//However, I is possible if you could allow your code do an import from sun's restricted packages like:
//
//import sun.security.x509.*;
//Here is an outline of code you are looking for:
//
//PrivateKey privkey = pair.getPrivate();
//X509CertInfo info = new X509CertInfo();
//Date from = new Date();
////Validity for next one year
//Date to = new Date(from.getTime() + (365) * 86400000l);
//
//CertificateValidity interval = new CertificateValidity(from, to);
//
//BigInteger sn = new BigInteger(64, new SecureRandom());
//X500Name owner = new X500Name(dn);
//
//info.set(X509CertInfo.VALIDITY, interval);
//info.set(X509CertInfo.SERIAL_NUMBER, new CertificateSerialNumber(sn));
//info.set(X509CertInfo.SUBJECT, new CertificateSubjectName(owner));
//info.set(X509CertInfo.ISSUER, new CertificateIssuerName(owner));
//info.set(X509CertInfo.KEY, new CertificateX509Key(pair.getPublic()));
//info.set(X509CertInfo.VERSION, new CertificateVersion(CertificateVersion.V3));
//AlgorithmId algo = new AlgorithmId(AlgorithmId.md5WithRSAEncryption_oid);
//info.set(X509CertInfo.ALGORITHM_ID, new CertificateAlgorithmId(algo));
//
//// Sign the cert
//X509CertImpl cert = new X509CertImpl(info);
//cert.sign(privkey, algorithm);
//
////cert object is ready to use
//Hope this helps
    //otro 
//To generate a certificate dynamically, you can use BouncyCastle and its X509V3CertificateGenerator class.
//
//First, generate a self-signed CA (with the CA basic constraint set), using keytool for example (look at the -ext option for details). This will be your custom CA.
//
//Export the certificate from that keystore (only the CA certificate, not its private key) and import it into the clients you're going to use.
//
//In your application, using that private key for signing with the X509V3CertificateGenerator, and make sure the Issuer DN you use matches the Subject DN of the CA cert you've generated above.
//
//Then, you'll need to configure the certificate generate with a Subject DN (or Subject Alternative Name) that matches the host name your client intended to contact. This may be the tricky bit if you intend to do this automatically as some sort of transparent proxy. (As far as I know, current versions of Java can't read the name coming from the SNI extension, at least not in advance or without doing more manual processing.) The easier way would certainly be to have this host name as a configurable option in your tool.
//
//To set it up without restarting the server, you could implement your own X509KeyManager that stays in place in the SSLContext you're using, but for which you keep a reference and custom accessors to re-configure the certificate later on. It's certainly not necessarily something "clean", and I haven't tried it, but it should work in principle. (You should certainly make sure the concurrency aspects are handled properly.)
//
//This might allow you not to have to shut down the listening socket, reconfigure the SSLContext and restart the socket. Considering that you might need to interact with your application anyway (to reconfigure the host name), this might be overkill.
    //
    //
    //otro mas 
//    As I understand it, if I do:
//
//keytool -genkeypair -alias foo
//it creates, in one step, certificate, a private key, and a public key.
//
//That's great. Now I can export the public portions of the certificate (the information about the subject of the certificate, and the public key), in a 'Privacy Enhanced Mail' (PEM) format as per RFC 1421 by doing:
//
//keytool -exportcert -alias foo -rfc > mycert.cer
//I can now give mycert.cer to the party that needs to verify signatures I generate with the private key. That private key remains private in the keystore (both the key and the store can be encrypted with a passphrase).
//
//Finally, it just remains to obtain the private key from the keystore at runtime in my program so that I can sign stuff such that the other party can verify I signed it.
//
//The guts of that (relying on the KeyStore doc as cheered along by Dr Heron Yang) is:
//
//// load the keystore, supplying the store password
//KeyStore jks = KeyStore.getInstance("JKS");
//jks.load(new FileInputStream(jksFile), jksPass);
//
//// get the 'entry'
//KeyStore.ProtectionParameter protParam = new KeyStore.PasswordProtection(password);
//KeyStore.PrivateKeyEntry pkEntry = (KeyStore.PrivateKeyEntry)
//    ks.getEntry("foo", protParam);
//
//// grab the bits from the private key
//PrivateKey myPrivateKey = pkEntry.getPrivateKey();
//Now I could hand myPrivateKey (assuming it was the right sort of key, of course), to something like:
//
//  // import java.security.*
//  Signature sig = Signature.getInstance("SHA1withRSA");
//  sig.initSign(myPrivateKey);
//  sig.update(mybytes);
//  return sig.sign();
//and I thus generate a signature which my other party (assuming they trust the certificate I supplied them before and can associate it with stuff I send them) can use to verify that it was really me who gave them the data.
    //
    //keystore tupo pkcs12
    //java.security.KeyStore.getInstance("PKCS12");
    //
    //
    //import cert
    //For add the certificate to your keystore is this:
//    keytool -importcert -keystore [keystore location, varies, but can be e.g.
// /etc/pki/java/cacerts] -storepass changeit -file /tmp/lb.cert -alias 
//newSelfSignedKey -noprompt
//    private void keyParGenerator() {
//        try {
//
//            KeyPairGenerator instance = KeyPairGenerator.getInstance("RSA");
//            KeyPair genKeyPair = instance.genKeyPair();
//            String format = javax.xml.bind.DatatypeConverter.printBase64Binary(genKeyPair.getPrivate().getEncoded());
//            System.out.println("format = " + format);
//            String format1 = javax.xml.bind.DatatypeConverter.printBase64Binary(genKeyPair.getPublic().getEncoded());
//            System.out.println("format1 = " + format1);
//        } catch (NoSuchAlgorithmException ex) {
//            Logger.getLogger(CustomCertificationAuthority.class.getName()).log(Level.SEVERE, null, ex);
//        }
//    }
//
//    private KeyPair genRSAKeyPair() {
//        // Get RSA key factory:
//        KeyPairGenerator kpg = null;
//        try {
//            kpg = KeyPairGenerator.getInstance("RSA");
//        } catch (NoSuchAlgorithmException e) {
////        log.error(e.getMessage());
//            e.printStackTrace();
//            return null;
//        }
//        // Generate RSA public/private key pair:
////    kpg.initialize(RSA_KEY_LEN);
//        KeyPair kp = kpg.genKeyPair();
//        return kp;
//    }
////and I generate the corresponding certificate:
//
//    private X509Certificate generateCertificate(String dn, KeyPair pair, int days, String algorithm)
//            throws GeneralSecurityException, IOException {
//        PrivateKey privkey = pair.getPrivate();
//        X509CertInfo info = new X509CertInfo();
//        Date from = new Date();
//        Date to = new Date(from.getTime() + days * 86400000l);
//        CertificateValidity interval = new CertificateValidity(from, to);
//        BigInteger sn = new BigInteger(64, new SecureRandom());
//        X500Name owner = new X500Name(dn);
//
//        info.set(X509CertInfo.VALIDITY, interval);
//        info.set(X509CertInfo.SERIAL_NUMBER, new CertificateSerialNumber(sn));
//        info.set(X509CertInfo.SUBJECT, new CertificateSubjectName(owner));
//        info.set(X509CertInfo.ISSUER, new CertificateIssuerName(owner));
//        info.set(X509CertInfo.KEY, new CertificateX509Key(pair.getPublic()));
//        info.set(X509CertInfo.VERSION, new CertificateVersion(CertificateVersion.V3));
//        AlgorithmId algo = new AlgorithmId(AlgorithmId.md5WithRSAEncryption_oid);
//        info.set(X509CertInfo.ALGORITHM_ID, new CertificateAlgorithmId(algo));
//
//        // Sign the cert to identify the algorithm that's used.
//        X509CertImpl cert = new X509CertImpl(info);
//        cert.sign(privkey, algorithm);
//
//        // Update the algorith, and resign.
//        algo = (AlgorithmId) cert.get(X509CertImpl.SIG_ALG);
//        info.set(CertificateAlgorithmId.NAME + "." + CertificateAlgorithmId.ALGORITHM, algo);
//        cert = new X509CertImpl(info);
//        cert.sign(privkey, algorithm);
//        return cert;
//    }
////Then I generate the cert signing request and I save it to csrFile file:
//
//    public static void writeCertReq(File csrFile, String alias, String keyPass, KeyStore ks)
//            throws KeyStoreException,
//            NoSuchAlgorithmException,
//            InvalidKeyException,
//            IOException,
//            CertificateException,
//            SignatureException,
//            UnrecoverableKeyException {
//
//        Object objs[] = getPrivateKey(ks, alias, keyPass.toCharArray());
//        PrivateKey privKey = (PrivateKey) objs[0];
//
//        PKCS10 request = null;
//
//        Certificate cert = ks.getCertificate(alias);
//        request = new PKCS10(cert.getPublicKey());
//        String sigAlgName = "MD5WithRSA";
//        Signature signature = Signature.getInstance(sigAlgName);
//        signature.initSign(privKey);
//        X500Name subject = new X500Name(((X509Certificate) cert).getSubjectDN().toString());
//        X500Signer signer = new X500Signer(signature, subject);
//        request.encodeAndSign(signer);
//        request.print(System.out);
//        FileOutputStream fos = new FileOutputStream(csrFile);
//        PrintStream ps = new PrintStream(fos);
//        request.print(ps);
//        fos.close();
//    }
////where
//
//    private static Object[] getPrivateKey(KeyStore ks, String alias, char keyPass[])
//            throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException {
//        key = null;
//        key = ks.getKey(alias, keyPass);
//        return (new Object[]{(PrivateKey) key, keyPass});
//    }
//
////    I see you've already gone over to the BouncyCastle side of the house but just in case anyone else was wondering; you can add the cert chain to the entry when putting the key into the KeyStore. For example
//// build your certs 
//    private void buildCerts() {
////KeyStore keyStore = KeyStore.getInstance("PKCS12");
////keyStore.load(new FileInputStream(""),"".toCharArray());// or null, null if it's a brand new store
////X509Certificate[] chain = new X509Certificate[2];
////chain[0] = _clientCert;
////chain[1] = _caCert;
////keyStore.setKeyEntry("Alias", _clientCertKey, password.toCharArray(), chain);
////keyStore.store([output stream], password.toCharArray());
//    }
////verify
//
//    int certVerify(byte certChain[][]) throws java.security.cert.CertificateException, KeyStoreException, IOException, NoSuchAlgorithmException {
//        CertificateFactory cf = CertificateFactory.getInstance("X509");
//        X509Certificate certx[] = new X509Certificate[10];
//        for (int i = 0; i < certChain.length; i++) {
//            certx[i] = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certChain[i]));
//        }
//
//        KeyStore keyStore = KeyStore.getInstance("JKS");
//        keyStore.load(new FileInputStream("cacerts.jks"), "123456".toCharArray());
//
//        TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
//        trustManagerFactory.init(keyStore);
//        return 0;
//    }
//
//    private void certVerifyV2(byte certChain[][]) throws java.security.cert.CertificateException {
////        CertificateFactory cf = CertificateFactory.getInstance("X.509");
////List<Certificate> certx = new ArrayList<>(certChain.length);
////for (byte[] c : certChain)
////  certx.add(cf.generateCertificate(new ByteArrayInputStream(c)));
////CertPath path = cf.generateCertPath(certx);
////CertPathValidator validator = CertPathValidator.getInstance("PKIX");
////KeyStore keystore = KeyStore.getInstance("JKS");
////try (InputStream is = Files.newInputStream(Paths.get("cacerts.jks"))) {
////  keystore.load(is, "changeit".toCharArray());
////}
////Collection<? extends CRL> crls;
////try (InputStream is = Files.newInputStream(Paths.get("crls.p7c"))) {
////  crls = cf.generateCRLs(is);
////}
////PKIXParameters params = new PKIXParameters(keystore);
////CertStore store = CertStore.getInstance("Collection", new CollectionCertStoreParameters(crls));
/////* If necessary, specify the certificate policy or other requirements 
//// * with the appropriate params.setXXX() method. */
////params.addCertStore(store);
/////* Validate will throw an exception on invalid chains. */
////PKIXCertPathValidatorResult r = (PKIXCertPathValidatorResult) validator.validate(path, params);
//    }
//
////bouncy castle gen cert
////public static X509Certificate sign(PKCS10CertificationRequest inputCSR, PrivateKey caPrivate, KeyPair pair)
////        throws InvalidKeyException, NoSuchAlgorithmException,
////        NoSuchProviderException, SignatureException, IOException,
////        OperatorCreationException, CertificateException {   
////
////    AlgorithmIdentifier sigAlgId = new DefaultSignatureAlgorithmIdentifierFinder()
////            .find("SHA1withRSA");
////    AlgorithmIdentifier digAlgId = new DefaultDigestAlgorithmIdentifierFinder()
////            .find(sigAlgId);
////
////    AsymmetricKeyParameter foo = PrivateKeyFactory.createKey(caPrivate
////            .getEncoded());
////    SubjectPublicKeyInfo keyInfo = SubjectPublicKeyInfo.getInstance(pair
////            .getPublic().getEncoded());
////
////    PKCS10CertificationRequestHolder pk10Holder = new PKCS10CertificationRequestHolder(inputCSR);
////    //in newer version of BC such as 1.51, this is 
////    //PKCS10CertificationRequest pk10Holder = new PKCS10CertificationRequest(inputCSR);
////
////    X509v3CertificateBuilder myCertificateGenerator = new X509v3CertificateBuilder(
////            new X500Name("CN=issuer"), new BigInteger("1"), new Date(
////                    System.currentTimeMillis()), new Date(
////                    System.currentTimeMillis() + 30 * 365 * 24 * 60 * 60
////                            * 1000), pk10Holder.getSubject(), keyInfo);
////
////    ContentSigner sigGen = new BcRSAContentSignerBuilder(sigAlgId, digAlgId)
////            .build(foo);        
////
////    X509CertificateHolder holder = myCertificateGenerator.build(sigGen);
////    X509CertificateStructure eeX509CertificateStructure = holder.toASN1Structure(); 
////    //in newer version of BC such as 1.51, this is 
////    //org.spongycastle.asn1.x509.Certificate eeX509CertificateStructure = holder.toASN1Structure(); 
////
////    CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");
////
////    // Read Certificate
////    InputStream is1 = new ByteArrayInputStream(eeX509CertificateStructure.getEncoded());
////    X509Certificate theCert = (X509Certificate) cf.generateCertificate(is1);
////    is1.close();
////    return theCert;
////    //return null;
////}
//    ///
//    //
//    //
//    //
//    //
//    //
//    //
//    //
//    //
//    //
//    ///
/////
//    // symmetric algorithm for data encryption
//    final String ALGORITHM = "AES";
//// Padding for symmetric algorithm
//    final String PADDING_MODE = "/CBC/PKCS5Padding";
//// character encoding
//    final String CHAR_ENCODING = "UTF-8";
//// provider for the crypto
//    final String CRYPTO_PROVIDER = "Entrust";
//// RSA algorithm used to encrypt symmetric key
//    final String RSA_ALGORITHM = "RSA/ECB/PKCS1Padding";
//// symmetric key size (128, 192, 256) if using 192+ you must have the Java
//// Cryptography Extension (JCE) Unlimited Strength Jurisdiction Policy Files
//// installed
//    int AES_KEY_SIZE = 256;
//
//    private byte[] encryptWithRSA(byte[] aesKey, X509Certificate cert)
//            throws NoSuchAlgorithmException, NoSuchPaddingException,
//            InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
//        // get the public key from the encryption certificate to encrypt with
//        PublicKey pubKey = cert.getPublicKey();
//
//        // get an instance of the RSA Cipher
//        Cipher rsaCipher = Cipher.getInstance(RSA_ALGORITHM);
//
//        // set the cipher to use the public key
//        rsaCipher.init(Cipher.ENCRYPT_MODE, pubKey);
//
//        // encrypt the aesKey
//        return rsaCipher.doFinal(aesKey);
//    }
//
//    private AESEncryptedContents encryptWithAes(byte[] dataToEncrypt)
//            throws NoSuchAlgorithmException, NoSuchPaddingException,
//            InvalidKeyException, IllegalBlockSizeException,
//            BadPaddingException, NoSuchProviderException {
//        // get the symmetric key generator
//        KeyGenerator keyGen = KeyGenerator.getInstance(ALGORITHM);
//        keyGen.init(AES_KEY_SIZE); // set the key size
//
//        // generate the key
//        SecretKey skey = keyGen.generateKey();
//
//        // convert to binary
//        byte[] rawAesKey = skey.getEncoded();
//
//        // initialize the secret key with the appropriate algorithm
//        SecretKeySpec skeySpec = new SecretKeySpec(rawAesKey, ALGORITHM);
//
//        // get an instance of the symmetric cipher
//        Cipher aesCipher = Cipher.getInstance(ALGORITHM + PADDING_MODE,
//                CRYPTO_PROVIDER);
//
//        // set it to encrypt mode, with the generated key
//        aesCipher.init(Cipher.ENCRYPT_MODE, skeySpec);
//
//        // get the initialization vector being used (to be returned)
//        byte[] aesIV = aesCipher.getIV();
//
//        // encrypt the data
//        byte[] encryptedData = aesCipher.doFinal(dataToEncrypt);
//
//        // package the aes key, IV, and encrypted data and return them
//        return new AESEncryptedContents(rawAesKey, aesIV, encryptedData);
//    }
//
//    private byte[] decryptWithAES(byte[] aesKey, byte[] aesIV,
//            byte[] encryptedData) throws NoSuchAlgorithmException,
//            NoSuchPaddingException, InvalidKeyException,
//            InvalidAlgorithmParameterException, IllegalBlockSizeException,
//            BadPaddingException, UnsupportedEncodingException,
//            NoSuchProviderException {
//        // initialize the secret key with the appropriate algorithm
//        SecretKeySpec skeySpec = new SecretKeySpec(aesKey, ALGORITHM);
//
//        // get an instance of the symmetric cipher
//        Cipher aesCipher = Cipher.getInstance(ALGORITHM + PADDING_MODE,
//                CRYPTO_PROVIDER);
//
//        // set it to decrypt mode with the AES key, and IV
//        aesCipher.init(Cipher.DECRYPT_MODE, skeySpec,
//                new IvParameterSpec(aesIV));
//
//        // decrypt and return the data
//        byte[] decryptedData = aesCipher.doFinal(encryptedData);
//
//        return decryptedData;
//    }
//
//    private byte[] decryptWithRSA(byte[] encryptedAesKey, PrivateKey privKey)
//            throws IllegalBlockSizeException, BadPaddingException,
//            InvalidKeyException, NoSuchAlgorithmException,
//            NoSuchPaddingException, NoSuchProviderException {
//        // get an instance of the RSA Cipher
//        Cipher rsaCipher = Cipher.getInstance(RSA_ALGORITHM, CRYPTO_PROVIDER);
//
//        // set the cipher to use the public key
//        rsaCipher.init(Cipher.DECRYPT_MODE, privKey);
//
//        // encrypt the aesKey
//        return rsaCipher.doFinal(encryptedAesKey);
//    }
}
