package anna_univ.ananthi;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Random;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class Ring {
	final static int N=4; //Number of ring members including the signer
	final static int l=1024;
	final static int b= (int) Math.pow(2,(l-1));
	public Ring() {
		
	}

	static BigInteger h(String M) throws NoSuchAlgorithmException
	{
			byte[] hash = MessageDigest.getInstance("SHA-1").digest(M.getBytes());
			return new BigInteger(1, hash);
	}
	
	static BigInteger E(BigInteger k, BigInteger y) throws NoSuchAlgorithmException
	{
		byte[] hash = MessageDigest.getInstance("SHA-1").digest((k.toString().concat(y.toString())).getBytes());
		return new BigInteger(1, hash);
	}
	
	static BigInteger g(BigInteger x,BigInteger e, BigInteger m) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException
	{
		BigInteger q,r;
		q=x.divide(m);
		r=x.mod(m);
		return (q.multiply(m)).add(r.modPow( e, m));
	}
	static Signature Sign(String M,RSAPublicKey[] pub,RSAPrivateKey signer_private) throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException
	{
		//Compute Symmetric key k=h(m)
		BigInteger k=h(M);
		//Pick a random glue value u for the signer
		Random randomGenerator = new Random();
		int u = randomGenerator.nextInt(b);
		//Compute v
		BigInteger v=E(k,BigInteger.valueOf(u));
		//Pick random glue values x for the non-signers
		BigInteger[] x=new BigInteger[4];
		for(int i=1;i<4;i++)
		{
			x[i]=BigInteger.valueOf(randomGenerator.nextInt(b));
		}
		//Compute y=g(x)
		BigInteger[] y=new BigInteger[4];
		for(int i=1;i<4;i++)
		{
			y[i]=g(x[i],pub[i].getPublicExponent(),pub[i].getModulus());
			v=E(k,v.xor(y[i]));
			System.out.println("y["+i+"]:"+y[i]);
		}
		//Compute x[0] for the signer
		y[0]= v.xor(BigInteger.valueOf(u));
		//Compute y[0] using signer's private key
		x[0]= g(y[0],signer_private.getPrivateExponent(),signer_private.getModulus());
		System.out.println("y[0]:"+y[0]);
		//Format the Signature
		Signature s=new Signature(pub, v, x);
		return s;
	}

	static boolean verify(String M,Signature s) throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException
	{
		//Compute Symmetric key k=h(m)
		BigInteger k=h(M);
		BigInteger v=s.v;
		BigInteger[] y=new BigInteger[4];
		for(int i=0;i<4;i++)
		{
			y[i]=g(s.X[i],s.public_keys[i].getPublicExponent(),s.public_keys[i].getModulus());
			v=E(k,v.xor(y[i]));
			System.out.println("y["+i+"]:"+y[i]);
		}
		System.out.println("V in verify:"+v);
		if(v.equals(s.v))return true;
		return false;
	}

	/**
	 * @param args
	 * @throws BadPaddingException 
	 * @throws IllegalBlockSizeException 
	 * @throws NoSuchPaddingException 
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidKeyException 
	 */
	public static void main(String[] args) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
		
		String message="Signature";
		//Number of members in the ring is 4
		
		
		RSAPrivateKey[] privateKey=new RSAPrivateKey[4];
		RSAPublicKey[] publicKey=new RSAPublicKey[4];
		KeyPairGenerator keyGen;
		try {
			
			
			 for (int i=0;i<4;i++)
			 {	
				 keyGen = KeyPairGenerator.getInstance("RSA");
				 keyGen.initialize(1024);
				 KeyPair keypair = keyGen.genKeyPair();
			     privateKey[i] = (RSAPrivateKey) keypair.getPrivate();
			     publicKey[i] = (RSAPublicKey) keypair.getPublic();
			     
			 }
		} 
		catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		long startTime = System.nanoTime();
		startTime = System.nanoTime();
		Signature s=Sign(message,publicKey,privateKey[0]);

		double timeMillis = (System.nanoTime()-startTime)*Math.pow(10, -6);
				System.out.println("Authentication took"+ timeMillis + "ms");
		System.out.println(verify(message,s));
	}

}
