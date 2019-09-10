package X509;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.text.SimpleDateFormat;

public class X509Parser {

    public static void main(String[] args) {
    	String filePath = "test/ca.cer";
    	if (args.length < 1) {
    		System.out.println("Didn't input the certificate file name."
    				+ "\nWill use default cer file of ./512b-rsa-example-cert.der");
    	} else {
    		filePath = args[0];
        	System.out.println("Parse the cer file " + filePath);
    	}
    	
        try {
            File file = new File(filePath);
            InputStream inputStream = new FileInputStream(file);
            //����X509������
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            //����֤�����
            X509Certificate oCert = (X509Certificate)cf.generateCertificate(inputStream);
            inputStream.close();
            SimpleDateFormat dateformat = new SimpleDateFormat("yyyy/MM/dd"); 
            String info = null;
            //���֤��汾
            info = String.valueOf(oCert.getVersion());
            System.out.println("�汾(Version):\n\t\t"+info);
            //���֤�����к�
            info = oCert.getSerialNumber().toString();
            System.out.println("���к�(Serial Number):\n\t\t"+info+"(0x"+oCert.getSerialNumber().toString(16)+")");

            info = oCert.getSigAlgOID();
            System.out.println("ǩ���㷨OID(Algorithm ID):\n\t\t"+info);

            //���֤��䷢����Ϣ
            info = oCert.getIssuerDN().getName();
            System.out.println("�䷢��(Issuer):\n\t\t"+info); 

            //���֤����Ч��
            Date beforedate = oCert.getNotBefore();
            info = dateformat.format(beforedate);
            System.out.println("��Ч�ڴ�(Not Before):\n\t\t"+info);
            Date afterdate = (Date) oCert.getNotAfter();
            info = dateformat.format(afterdate);
            System.out.println("   ��(Not After):\n\t\t"+info);

            //���֤��������Ϣ
            info = oCert.getSubjectDN().getName();
            System.out.println("(Subject):\n\t\t"+info); 

            info = oCert.getPublicKey().getAlgorithm();
            System.out.println("��Կ�㷨(Public Key Algorithm)��\n\t\t"+info);

            info = bytesToHex(oCert.getPublicKey().getEncoded());
            System.out.println("��Կ(Subject Public Key)��\n\t\t"+info);

            info = bytesToHex(oCert.getSignature());
            System.out.println("ǩ���㷨(Certificate Signature Algorithm)��\n\t\t" + oCert.getSigAlgName());
            System.out.println("ǩ��(Certificate Signature Algorithm)��\n\t\t"+info);

            byte[] byt = oCert.getExtensionValue("1.2.86.11.7.9");
            String strExt = byt == null ? "null" : new String(byt);
            System.out.println("֤����չ��:\n\t\t" + strExt);
            byt = oCert.getExtensionValue("1.2.86.11.7.1.8");
            String strExt2 = byt == null ? "null" : new String(byt);
            System.out.println("֤����չ��2:\n\t\t" + strExt2); 
        } catch (Exception e) {
            e.printStackTrace();
            return;
        }
    }
    
    public static String bytesToHex(byte[] bytes) {  
        StringBuffer sb = new StringBuffer();  
        for(int i = 0; i < bytes.length; i++) {  
            String hex = Integer.toHexString(bytes[i] & 0xFF);  
            if (hex.length() < 2){  
                sb.append(0);  
            } 
            sb.append(hex);
            if ((i+1)%16 == 0) {
                sb.append("\n\t\t");
            }
        }
        return sb.toString();  
    }
}
