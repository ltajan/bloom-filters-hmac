import java.math.*;
import java.util.BitSet;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.util.Formatter;
import java.util.Random;

public class BloomFilterHMAC {

	private BitSet storage;
	private int k;
	private String[] keySet;
	private BigInteger m;

	public BloomFilterHMAC(double m, int k, String keySet[]) {
		storage = new BitSet((int)m);
		storage.clear(); // set every bit to false
		
		this.m = new BigInteger(Integer.toString((int)m));
		this.k = k;
		this.keySet = keySet;
		
	}
	
	private String hmac(String item, String key) {
		try {
			SecretKeySpec signingKey = new SecretKeySpec(key.getBytes(), "HmacSHA1");
			Mac mac = Mac.getInstance("HmacSHA1");
			mac.init(signingKey);
			return bytesToHex(mac.doFinal(item.getBytes()));
		}
		catch(Exception e) {
			System.out.println("Exception occured by mac.");
			System.exit(1);
		}
		return null;
	}
	
	public String bytesToHex(byte[] bytes) {
		Formatter formatter = new Formatter();
		for(byte b : bytes) {
			formatter.format("%02x", b);
		}
		return formatter.toString();
	}

	public void add(String item) {
		for(int i=0; i<k; i++) {
			BigInteger hmac_as_bigint = new BigInteger(hmac(item, keySet[i]), 16);
			hmac_as_bigint = hmac_as_bigint.mod(m);
			int index = hmac_as_bigint.intValue();
			storage.set(index);
		}
	}


	public void addMultiIP(String start, String end) {
		System.out.println("start: "+ start);
                System.out.println("end: "+ end);

		String [] startTab = start.split("\\.");
                String [] endTab = end.split("\\.");

                
		int s1= Integer.parseInt(startTab[0]);
		int s2= Integer.parseInt(startTab[1]);
		int s3= Integer.parseInt(startTab[2]);
		int s4= Integer.parseInt(startTab[3]);

		int e1= Integer.parseInt(endTab[0]);
		int e2= Integer.parseInt(endTab[1]);
		int e3= Integer.parseInt(endTab[2]);
		int e4= Integer.parseInt(endTab[3]);
                
//                System.out.println("start: "+ s1+"."+ s2+"."+ s3+"."+ s4);
//		System.out.println("end: "+ e1+"."+ e2+"."+ e3+"."+ e4);
//		System.out.println("s1: "+ s1 + " s2: "+ s2+" s3: "+ s3 +" s4: "+ s4);
                int addNbr= (e1-s1)*(256*256*256)+(e2-s2)*(256*256)+(e3-s3)*(256)+(e4-s4);
                
                for(int i=0; i<=addNbr; i++) {
                    for(int j=0; j<k; j++) {
                        BigInteger hmac_as_bigint = new BigInteger(hmac(String.valueOf((s1+(s2+((s3+(s4+i)/256)/256))/256)%256)+"."+String.valueOf((s2+((s3+(s4+i)/256)/256))%256)+"."+String.valueOf((s3+(s4+i)/256)%256)+"."+String.valueOf((s4+i)%256), keySet[j]), 16);
                        hmac_as_bigint = hmac_as_bigint.mod(m);
                        int index = hmac_as_bigint.intValue();
                        storage.set(index); 
                    }
//                    System.out.println(String.valueOf((s1+(s2+((s3+(s4+i)/256)/256))/256)%256)+"."+String.valueOf((s2+((s3+(s4+i)/256)/256))%256)+"."+String.valueOf((s3+(s4+i)/256)%256)+"."+String.valueOf((s4+i)%256));
                }
                System.out.println((addNbr+1)+ " IP address(es) have been added.");           
//                for(int i=0; i<=(e4-s4); i++) {
//                    for(int j=0; j<k; j++) {
//                            BigInteger hmac_as_bigint = new BigInteger(hmac(String.valueOf(s1)+"."+String.valueOf(s2)+"."+String.valueOf(s3)+"."+String.valueOf(s4+i), keySet[j]), 16);
//                            hmac_as_bigint = hmac_as_bigint.mod(m);
//                            int index = hmac_as_bigint.intValue();
//                            storage.set(index);
//                    }
//                }
	}


	public void addAmountIP(String start, int n) {
//		System.out.println("start: "+ start);

		String [] startTab = start.split("\\.");

                
		int s1= Integer.parseInt(startTab[0]);
		int s2= Integer.parseInt(startTab[1]);
		int s3= Integer.parseInt(startTab[2]);
		int s4= Integer.parseInt(startTab[3]);

                
//                System.out.println("start: "+ s1+"."+ s2+"."+ s3+"."+ s4);
//		System.out.println("end: "+ e1+"."+ e2+"."+ e3+"."+ e4);
//		System.out.println("s1: "+ s1 + " s2: "+ s2+" s3: "+ s3 +" s4: "+ s4);
                int addNbr= n;
                
                for(int i=0; i<addNbr; i++) {
                    for(int j=0; j<k; j++) {
                        BigInteger hmac_as_bigint = new BigInteger(hmac(String.valueOf((s1+(s2+((s3+(s4+i)/256)/256))/256)%256)+"."+String.valueOf((s2+((s3+(s4+i)/256)/256))%256)+"."+String.valueOf((s3+(s4+i)/256)%256)+"."+String.valueOf((s4+i)%256), keySet[j]), 16);
                        hmac_as_bigint = hmac_as_bigint.mod(m);
                        int index = hmac_as_bigint.intValue();
                        storage.set(index); 
                    }
//                    System.out.println(String.valueOf((s1+(s2+((s3+(s4+i)/256)/256))/256)%256)+"."+String.valueOf((s2+((s3+(s4+i)/256)/256))%256)+"."+String.valueOf((s3+(s4+i)/256)%256)+"."+String.valueOf((s4+i)%256));
                }
//                System.out.println((addNbr)+ " IP address(es) have been added.");           
//                for(int i=0; i<=(e4-s4); i++) {
//                    for(int j=0; j<k; j++) {
//                            BigInteger hmac_as_bigint = new BigInteger(hmac(String.valueOf(s1)+"."+String.valueOf(s2)+"."+String.valueOf(s3)+"."+String.valueOf(s4+i), keySet[j]), 16);
//                            hmac_as_bigint = hmac_as_bigint.mod(m);
//                            int index = hmac_as_bigint.intValue();
//                            storage.set(index);
//                    }
//                }
	}





	
	public boolean contains(String item) {
		for(int i=0; i<k; i++) {
			BigInteger hmac_as_bigint = new BigInteger(hmac(item, keySet[i]), 16);
			hmac_as_bigint = hmac_as_bigint.mod(m);
			int index = hmac_as_bigint.intValue();
			if(storage.get(index) == false) {
				return false;
			}
		}
		return true;
	}



	public static boolean inclusion(BloomFilterHMAC A, BloomFilterHMAC B) {
		BitSet temp= new BitSet(A.m.intValue());
		temp = A.storage.get(0,A.m.intValue());
                temp.flip(0, A.m.intValue());
		temp.or(B.storage);
//		temp.and(A.storage);
		if (temp.cardinality()==A.m.intValue())
			return true;
		else return false;
	}


	public static int disjointness(BloomFilterHMAC A, BloomFilterHMAC B) {
		BitSet temp= new BitSet(A.m.intValue());
		temp = A.storage.get(0,A.m.intValue());
		temp.and(B.storage);
		return temp.cardinality();
	}


	public static float sInter(int n, int n2, int k, int m){
                
		return (float)n*n2*k*(k-1)/m;

	}
        
        public static void testDisjointness (int rounds, int m, int k){
            
            Random rnd = new Random();
            int res=0;
            int OA;
            int OAmax=0;
            int OAmin=1000000;
            int OB;
            int OBmax=0;
            int OBmin=10000000;
            int S;
            int Smax=0;
            int Smin=10000000;
            double Smean=0;
                       
            for(int i=0; i<rounds; i++){         
                
                String keySet[] = new String[k];
		for(int j=0; j<k; j++) {
			keySet[j] = "ok"+ rnd.nextInt(); //change this to something you want, maybe static keys? 
//		System.out.println("keySet["+i+"]["+j+"]:"+ keySet[j]);
                }
                
                BloomFilterHMAC bf1 = new BloomFilterHMAC(m, k, keySet);
		BloomFilterHMAC bf2 = new BloomFilterHMAC(m, k, keySet);
                bf1.addMultiIP((10+(i/255))+"."+(i%255)+".200.0", (10+(i/255))+"."+(i%255)+".200.099");
                bf2.addMultiIP((100+(i/255))+"."+(i%255)+".200.0", (100+(i/255))+"."+(i%255)+".203.231");
                
//                bf2.add((10+(i/255))+"."+(i%255)+".200.0");
//                bf2.add((10+(i/255))+"."+(i%255)+".200.1");
//                bf2.add((10+(i/255))+"."+(i%255)+".200.2");

//                bf2.add((100+i)+".148.201.0");
//                bf2.add((100+i)+".148.202.0");
                S=disjointness(bf1, bf2);
                System.out.println("S: "+ S + " ");
                Smean=Smean+S;
                if (S>Smax)
                    Smax=S;                
                if (S<Smin)
                    Smin=S;
                if (S<500)
                    res++;
                
                BitSet temp= new BitSet(bf1.m.intValue());
                temp = bf1.storage.get(0,bf1.m.intValue());
                
                System.out.println("#(1)="+temp.cardinality());
                OA=(100*k)-temp.cardinality();
                if (OA>OAmax)
                    OAmax=OA;                
                if (OA<OAmin)
                    OAmin=OA;
                System.out.println("# of overlapping="+OA);
 

                BitSet temp2= new BitSet(bf2.m.intValue());
                temp2 = bf2.storage.get(0,bf2.m.intValue());
                
                System.out.println("#(1)="+temp2.cardinality());
                OB=(1000*k)-temp2.cardinality();
                if (OB>OBmax)
                    OBmax=OB;                
                if (OB<OBmin)
                    OBmin=OB;
                System.out.println("# of overlapping="+OB);
                   
            }
            System.out.println("# of good: "+res);
            float resF=res*100/rounds;
            System.out.println("Disjointness: "+resF+"% of success.");
            System.out.println("OA min: "+OAmin);
            System.out.println("OA max: "+OAmax);
            System.out.println("OB min: "+OBmin);
            System.out.println("OB max: "+OBmax);
            System.out.println("S min: "+Smin);
            System.out.println("S max: "+Smax);
            System.out.println("S mean: "+Smean/rounds);

              
        }
        
        
        public static void testInclusion (int rounds, int m, int k){
            
            Random rnd = new Random();
            int res=0;
            int S;
            int Smax=0;
                       
            for(int i=0; i<rounds; i++){         
                
                String keySet[] = new String[k];
		for(int j=0; j<k; j++) {
			keySet[j] = "ok"+ rnd.nextInt(); //change this to something you want, maybe static keys? 
//		System.out.println("keySet["+i+"]["+j+"]:"+ keySet[j]);
                }
                
                BloomFilterHMAC bf1 = new BloomFilterHMAC(m, k, keySet);
		BloomFilterHMAC bf2 = new BloomFilterHMAC(m, k, keySet);
                bf1.addMultiIP((100+(i/255))+"."+(i%255)+".200.0", (100+(i/255))+"."+(i%255)+".203.231");
                bf2.addMultiIP((100+(i/255))+"."+(i%255)+".200.0", (100+(i/255))+"."+(i%255)+".203.230");
                
                bf2.add((10+(i/255))+"."+(i%255)+".200.0");
                
                System.out.println(i);

                System.out.println(inclusion(bf1,bf2));

                if(inclusion(bf1, bf2))
                    res++;
                
                   
            }
//            float resF=res*100/rounds;
            System.out.println("Inclusion: "+res+" errors.");
//            System.out.println("S max: "+Smax);

              
        }
        
        
        public static void testTime (int rounds, int m, int k){
            
            Random rnd = new Random();
            int res=0;
            int S;
            int Smax=0;
            
            String keySet[] = new String[k];
		for(int j=0; j<k; j++) {
			keySet[j] = "ok"+ rnd.nextInt(); //change this to something you want, maybe static keys? 
//		System.out.println("keySet["+i+"]["+j+"]:"+ keySet[j]);
                }
            
            BloomFilterHMAC bf1 = new BloomFilterHMAC(m, k, keySet);
            BloomFilterHMAC bf2 = new BloomFilterHMAC(m, k, keySet);
            bf1.addMultiIP("148.148.200.0", "148.148.203.231");
            bf2.addMultiIP("148.149.200.0", "148.149.203.231");
            
            long startTime = System.nanoTime();        
            for(int i=0; i<rounds; i++){         
                
//                String keySet[] = new String[k];
//		for(int j=0; j<k; j++) {
//			keySet[j] = "ok"+ rnd.nextInt(); //change this to something you want, maybe static keys? 
////		System.out.println("keySet["+i+"]["+j+"]:"+ keySet[j]);
//                }
//            disjointness(bf1, bf2);
            inclusion(bf1, bf2);
     
                
//                BloomFilterHMAC bf1 = new BloomFilterHMAC(m, k, keySet);
//		BloomFilterHMAC bf2 = new BloomFilterHMAC(m, k, keySet);
//                bf1.addMultiIP((100+i)+".148.200.0", (100+i)+".148.211.0");
//                bf2.addMultiIP((100+i)+".148.200.0", (100+i)+".148.222.0");
                
//                bf1.add((100+i)+".149.200.0");

//                System.out.println(inclusion(bf1,bf2));
//                if(inclusion(bf1, bf2))
//                    res++;
//                
//                   
            }
//            float resF=res*100/rounds;
//            System.out.println("Inclusion: "+res+" errors.");
//            System.out.println("S max: "+Smax);

              
      long stopTime = System.nanoTime();
      long elapsedTime = stopTime - startTime;
      elapsedTime = elapsedTime/ rounds;
//      elapsedTime = elapsedTime/ 1000000;
      System.out.println(elapsedTime);
        }
        
             public static void attack (int rounds, int m, int k){
            
            Random rnd = new Random();
            int res=0;
            int S;
            int Smax=0;
                       
            for(int i=0; i<rounds; i++){         
                
                String keySet[] = new String[k];
		for(int j=0; j<k; j++) {
			keySet[j] = "ok"+ rnd.nextInt(); //change this to something you want, maybe static keys? 
//		System.out.println("keySet["+i+"]["+j+"]:"+ keySet[j]);
                }
                
                BloomFilterHMAC bf1 = new BloomFilterHMAC(m, k, keySet);
		BloomFilterHMAC bf2 = new BloomFilterHMAC(m, k, keySet);
                bf1.addMultiIP((100+i)+".148.200.0", (100+i)+".148.201.215");
                bf2.addMultiIP((100+i)+".158.200.0", (100+i)+".158.202.108");
                
//                bf1.add((100+i)+".149.200.0");
                BitSet temp= new BitSet(bf1.m.intValue());
                temp = bf1.storage.get(0,bf1.m.intValue());
                
                System.out.println("#(1)="+temp.cardinality());
                System.out.println("# of overlapping="+((1024*k)-temp.cardinality()));
 

                BitSet temp2= new BitSet(bf2.m.intValue());
                temp2 = bf2.storage.get(0,bf2.m.intValue());
                
                System.out.println("#(1)="+temp2.cardinality());
                System.out.println("# of overlapping="+((2305*k)-temp2.cardinality()));             
                
//                if(inclusion(bf1, bf2))
//                    res++;
//                
                   
            }
//            float resF=res*100/rounds;
//            System.out.println("Inclusion: "+res+" errors.");
//            System.out.println("S max: "+Smax);

              
        }
           
        public static void testOB (int rounds, int m, int k){
            
            Random rnd = new Random();
            int res=0;
            int S;
            int Smax=0;
            int [] tab= new int[1000];
            int t=0;
            int tmax=0;
            int tmin=10000;
                       
            for(int i=0; i<rounds; i++){         
                
                String keySet[] = new String[k];
		for(int j=0; j<k; j++) {
			keySet[j] = "ok"+ rnd.nextInt(); //change this to something you want, maybe static keys? 
//		System.out.println("keySet["+i+"]["+j+"]:"+ keySet[j]);
                }
                
                BloomFilterHMAC bf1 = new BloomFilterHMAC(m, k, keySet);
                bf1.addMultiIP((100+i)+".148.200.0", (100+i)+".148.203.231");
                
//                bf1.add((100+i)+".149.200.0");
                BitSet temp= new BitSet(bf1.m.intValue());
                temp = bf1.storage.get(0,bf1.m.intValue());
                t=(1000*k)-temp.cardinality();
                tab[t]++;
                if (t>tmax)
                    tmax=t;                
                if (t<tmin)
                    tmin=t;
//               System.out.println("#(1)="+temp.cardinality());
               System.out.println("# of overlapping="+((1000*k)-temp.cardinality()));                          
//                if(inclusion(bf1, bf2))
//                    res++;
//                
            }
            for(int i=tmin; i<tmax+1;i++){
                System.out.println("tab["+i+"]: "+tab[i]);
                
            }
//            float resF=res*100/rounds;
//            System.out.println("Inclusion: "+res+" errors.");
//            System.out.println("S max: "+Smax);

              
        }
        
        
        public static void testOB2 (int rounds, int m, int k){
            
            Random rnd = new Random();
            int n=1000;
            int nP=1000;
            int res=0;
            int [] tabS= new int[100000];
            int S=0;
            int Smax=0;
            int Smin=10000;
            int [] tab1= new int[1000000];
            int t1=0;
            int t1max=0;
            int t1min=10000;
            double t1moy=0;
            double s1=0;
            int [] tab2= new int[1000000];
            int t2=0;
            int t2max=0;
            int t2min=10000;
            double t2moy=0;
            double Smoy=0;
            double s2=0;
            double s3=0;

                       
            for(int i=0; i<rounds; i++){         
                
                String keySet[] = new String[k];
		for(int j=0; j<k; j++) {
			keySet[j] = "ok"+ rnd.nextInt(); //change this to something you want, maybe static keys? 
//		System.out.println("keySet["+i+"]["+j+"]:"+ keySet[j]);
                }
                
                BloomFilterHMAC bf1 = new BloomFilterHMAC(m, k, keySet);
                BloomFilterHMAC bf2 = new BloomFilterHMAC(m, k, keySet);
                

                bf1.addMultiIP((10+(i/255))+"."+(i%255)+".200.0", (10+(i/255))+"."+(i%255)+".203.231");
                bf2.addMultiIP((100+(i/255))+"."+(i%255)+".200.0", (100+(i/255))+"."+(i%255)+".203.231");
                
//                bf2.add((10+(i/255))+"."+(i%255)+".200.0");
//                bf2.add((10+(i/255))+"."+(i%255)+".200.1");
//                bf2.add((10+(i/255))+"."+(i%255)+".200.2");
                S=disjointness(bf1, bf2);
                tabS[S]++;
                if (S>Smax)
                    Smax=S;                
                if (S<Smin)
                    Smin=S;
                
//                bf1.add((100+i)+".149.200.0");
                BitSet temp1= new BitSet(bf1.m.intValue());
                temp1 = bf1.storage.get(0,bf1.m.intValue());
                t1=(n*k)-temp1.cardinality();
                tab1[t1]++;
                if (t1>t1max)
                    t1max=t1;                
                if (t1<t1min)
                    t1min=t1;
                
                
                
                
                
                BitSet temp2= new BitSet(bf2.m.intValue());
                temp2 = bf2.storage.get(0,bf2.m.intValue());
                t2=(nP*k)-temp2.cardinality();
                tab2[t2]++;
                if (t2>t2max)
                    t2max=t2;                
                if (t2<t2min)
                    t2min=t2;
                
                
                
                                
//               System.out.println("#(1)="+temp.cardinality());
//               System.out.println("# of overlapping="+((100*k)-temp.cardinality()));                          
                if(inclusion(bf1, bf2))
                    res++;
                
            }

             for(int i=t1min; i<t1max+1;i++){
                t1moy=t1moy+(tab1[i]*i);
            } 
            t1moy=t1moy/rounds;
            System.out.println("moyenne: "+t1moy);

            
            System.out.println("tab1"); 
            for(int i=t1min; i<t1max+1;i++){
                System.out.println("("+i+","+tab1[i]/10.0+")");
                for(int j=0; j<tab1[i];j++){
                    s1=s1+Math.pow((i-t1moy),2);
                }
            }
            s1=s1/rounds;
            s1= Math.sqrt(s1);
            System.out.println("stand dev: "+s1);
            
            
            
            for(int i=t2min; i<t2max+1;i++){
                t2moy=t2moy+(tab2[i]*i);
            } 
            t2moy=t2moy/rounds;
            System.out.println("moyenne: "+t2moy);
            
            System.out.println("tab2"); 
            for(int i=t2min; i<t2max+1;i++){
                System.out.println("("+i+","+tab2[i]/10.0+")");      
                for(int j=0; j<tab2[i];j++){
                    s2=s2+Math.pow((i-t2moy),2);
                }
            }
            s2=s2/rounds;
            s2= Math.sqrt(s2);
            System.out.println("stand dev: "+s2);
            
            
            
            for(int i=Smin; i<Smax+1;i++){
                Smoy=Smoy+(tabS[i]*i);
            } 
            Smoy=Smoy/rounds;
            System.out.println("moyenne: "+Smoy);
            
            
            
            System.out.println("tabS"); 
            for(int i=Smin; i<Smax+1;i++){
                System.out.println("("+i+","+tabS[i]/1000.0+")"); 
                for(int j=0; j<tabS[i];j++){
                    s3=s3+Math.pow((i-Smoy),2);
                }
            }
            
            s3=s3/rounds;
            s3= Math.sqrt(s3);
            System.out.println("stand dev: "+s3);
            
            
            
            float resF=res*100/rounds;
            System.out.println("Inclusion: "+res+" errors.");
            System.out.println("S max: "+Smax);

              
        }
        
        
        
        public static void attack2(int rounds, int m, int k, int k1, int k2, int oba1, int oba2, int obb1, int obb2){
            
            Random rnd = new Random();
            
            int[] L= new int[k2+1];
            
            
//            for(int r=0; r<rounds; r++){
                
            
            
            int[] L1= new int[k2-k1+1];
            int[] L2= new int[k2-k1+1];
            int t1;
            int t2;

           
            String keySet[] = new String[k];
            for(int j=0; j<k; j++) {
		keySet[j] = "ok"+ rnd.nextInt(); //change this to something you want, maybe static keys? 
//		System.out.println("keySet["+i+"]["+j+"]:"+ keySet[j]);
                }
                
            BloomFilterHMAC bf1 = new BloomFilterHMAC(m, k, keySet);
            BloomFilterHMAC bf2 = new BloomFilterHMAC(m, k, keySet);
            bf1.addMultiIP("100.148.200.0", "100.148.200.099"); /*100 IP  */
//            bf2.addMultiIP("100.158.200.0", "100.158.203.231"); /*1000 IP  */
//            bf1.addMultiIP("100.148.200.0", "100.148.200.009"); /*10 IP  */
            bf2.addMultiIP("100.158.200.0", "100.158.200.099");  /*100 IP  */
            
            
            
            
            
            
            BitSet temp1= new BitSet(bf1.m.intValue());
            temp1 = bf1.storage.get(0,bf1.m.intValue());
            t1=temp1.cardinality();
            
            BitSet temp2= new BitSet(bf2.m.intValue());
            temp2 = bf2.storage.get(0,bf2.m.intValue());
            t2=temp2.cardinality();
            
            System.out.println("#1 in BFA: "+t1);
            System.out.println("#1 in BFB: "+t2);
            
            
            for (int i=oba1; i<= oba2; i++){      
                for (int j=k1; j<=k2; j++){
                    if((t1+i)%j==0)
                        L1[(j-k1)]++;
                }
            }
            
            for (int i=obb1; i<= obb2; i++){      
                for (int j=k1; j<=k2; j++){
                    if((t2+i)%j==0)
                        L2[(j-k1)]++;
                }
            }
            
            
            for (int i=k1; i<= k2; i++){
                if((L1[i-k1]*L2[i-k1])>0)
                L[i]++;
            }
            
            System.out.println("lambda_A: "+lambda(L1));
            System.out.println("lambda_B: "+lambda(L2));
            System.out.println("lambda: "+lambda(L));

//            }
            System.out.println("lambda: "+lambdaPrint(L, k1));
        }
        
        
        
        
        
        public static void attack3(float rounds, int m, int k, int k1, int k2){
            
            Random rnd = new Random();
            
            int n=100;
            int nP=1000;
            int res=0;
            int [] tabS= new int[100000];
            int S=0;
            int Smax=0;
            int Smin=10000;
            double [] tab1= new double[1000000];
            int t1=0;
            int t1max=0;
            int t1min=10000;
            double t1moy=0;
            double s1=0;
            double [] tab2= new double[1000000];
            int t2=0;
            int t2max=0;
            int t2min=10000;
            double t2moy=0;
            double s2=0;
            
            
            
            
            for(int i=0; i<rounds; i++){         
                
                String keySet[] = new String[k];
		for(int j=0; j<k; j++) {
			keySet[j] = "ok"+ rnd.nextInt(); //change this to something you want, maybe static keys? 
//		System.out.println("keySet["+i+"]["+j+"]:"+ keySet[j]);
                }
                
                BloomFilterHMAC bf1 = new BloomFilterHMAC(m, k, keySet);
                BloomFilterHMAC bf2 = new BloomFilterHMAC(m, k, keySet);
                System.out.println("Round "+(i+1)+":");
                bf1.addMultiIP((100+i)+".148.200.0", (100+i)+".148.200.099");
                bf2.addMultiIP((100+i)+".158.200.0", (100+i)+".158.203.231");
//                S=disjointness(bf1, bf2);
//                tabS[S]++;
//                if (S>Smax)
//                    Smax=S;                
//                if (S<Smin)
//                    Smin=S;
                
//                bf1.add((100+i)+".149.200.0");
                BitSet temp1= new BitSet(bf1.m.intValue());
                temp1 = bf1.storage.get(0,bf1.m.intValue());
                t1=(n*k)-temp1.cardinality();
                tab1[t1]++;
                if (t1>t1max)
                    t1max=t1;                
                if (t1<t1min)
                    t1min=t1;
                
                
                
                
                
                BitSet temp2= new BitSet(bf2.m.intValue());
                temp2 = bf2.storage.get(0,bf2.m.intValue());
                t2=(nP*k)-temp2.cardinality();
                tab2[t2]++;
                if (t2>t2max)
                    t2max=t2;                
                if (t2<t2min)
                    t2min=t2;
                                            
//               System.out.println("#(1)="+temp.cardinality());
//               System.out.println("# of overlapping="+((100*k)-temp.cardinality()));                          
//                if(inclusion(bf1, bf2))
//                    res++;
//                
            }
            
            
            
            System.out.println("tab1");
            System.out.println("t1min: "+t1min);
            System.out.println("t1max: "+t1max); 
            for(int i=t1min; i<t1max+1;i++){
                System.out.println("("+i+","+tab1[i]/rounds*100+")");
                tab1[i]=tab1[i]+0.1;
            }         
            System.out.println("tab2");
            System.out.println("t2min: "+t2min);
            System.out.println("t2max: "+t2max); 
            for(int i=t2min; i<t2max+1;i++){
                System.out.println("("+i+","+tab2[i]/rounds*100+")");
                tab2[i]=tab2[i]+0.1;
            }
            
            
            
            
            
            
            double[] L= new double[k2+1];
            double[] L1= new double[k2-k1+1];
            double[] L2= new double[k2-k1+1];
            int X1;
            int X2;
            
            String keySet[] = new String[k];
            for(int j=0; j<k; j++) {
		keySet[j] = "ok"+ rnd.nextInt(); //change this to something you want, maybe static keys? 
//		System.out.println("keySet["+i+"]["+j+"]:"+ keySet[j]);
                }
            BloomFilterHMAC bf1 = new BloomFilterHMAC(m, k, keySet);
            BloomFilterHMAC bf2 = new BloomFilterHMAC(m, k, keySet);
            bf1.addMultiIP("100.148.200.0", "100.148.200.099"); /*100 IP  */
            bf2.addMultiIP("100.158.200.0", "100.158.203.231"); /*1000 IP  */
//            bf1.addMultiIP("100.148.200.0", "100.148.200.009"); /*10 IP  */
//            bf2.addMultiIP("100.158.200.0", "100.158.200.099");  /*100 IP  */
//            bf1.addMultiIP("100.148.200.0", "100.148.200.009");
//            bf2.addMultiIP("100.158.200.0", "100.158.200.099");
            
            
            BitSet temp1= new BitSet(bf1.m.intValue());
            temp1 = bf1.storage.get(0,bf1.m.intValue());
            X1=temp1.cardinality();
            
            BitSet temp2= new BitSet(bf2.m.intValue());
            temp2 = bf2.storage.get(0,bf2.m.intValue());
            X2=temp2.cardinality();
            
            System.out.println("#1 in BFA: "+X1);
            System.out.println("#1 in BFB: "+X2);
            
            
            for (int i=t1min; i<=t1max; i++){      
                for (int j=k1; j<=k2; j++){
                    if((X1+i)%j==0)
                        L1[(j-k1)]=tab1[i];
                }
            }
            
            for (int i=t2min; i<= t2max; i++){      
                for (int j=k1; j<=k2; j++){
                    if((X2+i)%j==0)
                        L2[(j-k1)]=tab2[i];
                }
            }
            
            double maxWeight=0.0;
            for (int i=k1; i<= k2; i++){
                if((L1[i-k1]*L2[i-k1])>0)
                L[i]=L1[i-k1]+L2[i-k1];
                if(maxWeight<L[i])
                    maxWeight=L[i];
            }
//            System.out.println("500: "+L[500]);

//            System.out.println("maxWeight: "+maxWeight);

            
            for (int i=k1; i<=k2; i++)
                L[i]=L[i]/maxWeight;
            
//            System.out.println("lambda_A: "+lambda(L1));
//            System.out.println("lambda_B: "+lambda(L2));
//            System.out.println("lambda: "+lambda(L));

            
            System.out.println("lambda: "+lambdaPrintDouble(L, k1));
            
            
            
            
            
            
            
        }        
        
        public static int lambda(int [] L){
            
            int res=0;
            for(int i=0; i<L.length;i++){
                if(L[i]==1)
                    res++;
            }
            return res;
        }
        
        
        
                public static int lambdaPrint(int [] L, int k1){
            
            int res=0;
            int j=1;
            for(int i=0; i<L.length;i++){
                if(L[i]>=1){
                    res++;
                    System.out.println("lambda "+j+": "+i+" "+L[i]/10.0);
                    j++;
                }    
            }
            return res;
        }
        
        
                public static int lambdaPrintDouble(double [] L, int k1){
            
            int res=0;
            int j=1;
            for(int i=0; i<L.length;i++){
                if(L[i]>0){
                    res++;
                    System.out.println("lambda "+j+": "+i+" "+ String.format("%.2f",L[i]));
                    j++;
                }    
            }
            return res;
        }
        
        
        public static double setm(int nkey, int nw, int nL2, int nkeyL){
            double m =100000;
            double x;
            
//            double pA;
//            double pB;
            
//            pA=1-Math.pow((1-(1/m)),(nkey*nw));
//            System.out.println("pA: " + (1-Math.pow((1-(1/m)),(nkey*nw))));

            x= m * (1-Math.pow((1-(1/m)),(nkey*nw))) * (1-Math.pow((1-(1/m)),(nkey*nL2)));
//            System.out.println("x: " + x);
//            System.out.println("x: " + (1.1*x));

            while((1.1*x)>nkeyL){
                m+=100;
                x= m * (1-Math.pow((1-(1/m)),(nkey*nw))) * (1-Math.pow((1-(1/m)),(nkey*nL2)));
            }
            System.out.println("m: " + m);
            return m;
            
        }
               
        
        public static int setnkey(int nkeyL, int nkeyU){
            
            int nkey;
            Random rndnkey =new Random();
            nkey= rndnkey.nextInt((nkeyU-nkeyL)+1) + nkeyL;
            System.out.println("nkey: "+nkey);

            return nkey;
        }
        
        
        
        public static double [] completeProtocol(int nw, int nL1, int ZL1w, int nL2, int ZprimeL2w, int rounds){
            
            double [] res= new double[9];
            Random rnd = new Random();

            int nkeyL= 500;
            int nkeyU= 2000;
            int nkey;
            double m;
            
            int cptInc= 0;
            int cptDis= 0;
            
            long startTime;
            long endTime;
            long elapsedTime;
            long wTime=0;
            long l1Time=0;
            long l2Time=0;
            long incTime=0;
            long disTime=0;

            
            /*    Parameters Generation    */
            nkey=setnkey(nkeyL, nkeyU);
            m=setm(nkey, nw, nL2, nkeyL);
            
                       
            /*    Keys Generation    */
            for(int i=0; i<rounds; i++){
                System.out.println("i: "+i);
                String keySet[] = new String[nkey];
		for(int j=0; j<nkey; j++) {
			keySet[j] = "ok"+ rnd.nextInt(); //change this to something you want, maybe static keys? 
                }
                System.out.println("nW: "+nw);
                System.out.println("nL1: "+nL1);
                System.out.println("nL2: "+nL2);
                System.out.println("ZL1w: "+ZL1w);
                System.out.println("ZprimeL2w: "+ZprimeL2w);
                

                
                /*    Bloom Filters Generation    */
                BloomFilterHMAC bfw = new BloomFilterHMAC(m, nkey, keySet);
                BloomFilterHMAC bfL1 = new BloomFilterHMAC(m, nkey, keySet);
                BloomFilterHMAC bfL2 = new BloomFilterHMAC(m, nkey, keySet);

                startTime = System.nanoTime();
                bfw.addAmountIP((10+(i/255))+"."+(i%255)+".200.0", nw);
                endTime = System.nanoTime();
                elapsedTime = endTime - startTime;
                wTime+=elapsedTime;
                
                startTime = System.nanoTime();
                bfL1.addAmountIP((10+(i/255))+"."+(i%255)+".200.0", (nL1-ZL1w));
                bfL1.addAmountIP((100+(i/255))+"."+(i%255)+".200.0", (ZL1w));
                endTime = System.nanoTime();
                elapsedTime = endTime - startTime;
                l1Time+=elapsedTime;
                
                startTime = System.nanoTime();
                bfL2.addAmountIP((100+(i/255))+"."+(i%255)+".200.0", (nL2-ZprimeL2w));
                bfL2.addAmountIP((10+(i/255))+"."+(i%255)+".200.0", ZprimeL2w);
                endTime = System.nanoTime();
                elapsedTime = endTime - startTime;
                l2Time+=elapsedTime;
            
                /*    Inclusiveness    */
                startTime = System.nanoTime();
                if(inclusion(bfL1, bfw)){
                    if(ZL1w!=0){
                        System.out.println("ici");
                        cptInc++;   

                    }
                }
                else{
                    if(ZL1w==0){
                       System.out.println("la");
                       cptInc++;  
                    }
                }
                endTime = System.nanoTime();
                elapsedTime = endTime - startTime;
                incTime+=elapsedTime;
            
                /*    Disjointness    */
                startTime = System.nanoTime();
                System.out.println("Dis: "+disjointness(bfw, bfL2));
                if(disjointness(bfw, bfL2)>nkeyL){
                    if(ZprimeL2w==0){
                        cptDis++;
                        System.out.println("ici");
                    }
                }
                else{
                    if(ZprimeL2w!=0){
                        cptDis++;
                        System.out.println("la");
                    }
                }            
                endTime = System.nanoTime();
                elapsedTime = endTime - startTime;
                disTime+=elapsedTime;
            
            }
            
//            System.out.println("Inclusion error(s): "+ cptInc);
//            System.out.println("Disjointness error(s): "+ cptDis);

            
            res[0]=nkey;
            res[1]=m;
            res[2]=(cptInc/rounds*100);
            res[3]=(cptDis/rounds*100);
            res[4]=(wTime/rounds/1000000);
            res[5]=(l1Time/rounds/1000000);
            res[6]=(l2Time/rounds/1000000);
            res[7]=(incTime/rounds/1000000);
            res[8]=(disTime/rounds/1000000);

            return res;
        }
        
        
        
        
        
        
        
	public static void main(String[] args) {			
//		int m = 2147483647;
                int m= 60000000;
		int k = 500;
                int k1=50;
                int k2=5000;
                int oba1=500;
                int oba2=1000;
                int obb1=500;
                int obb2=1000;
		
//		String keySet[] = new String[k];
//		for(int i=0; i<k; i++) {
//			keySet[i] = "random key" + i; //change this to something you want, maybe static keys? 
//		}
		
//                BloomFilterHMAC bf1 = new BloomFilterHMAC(m, k, keySet);
//		BloomFilterHMAC bf2 = new BloomFilterHMAC(m, k, keySet);
//                
//                bf1.add("255.255.248.105");
//                bf1.add("255.255.248.106");
//                bf1.add("255.255.248.107");
//
//                
//                bf2.add("255.255.248.105");
//                bf2.add("255.255.248.106");
//                bf2.add("255.255.248.107");
//                bf2.add("255.255.248.108");
//                System.out.println(inclusion(bf1, bf2) + " ");
                
                
                
//		System.out.println("m: "+ m);
//		System.out.println("k: "+ k);
//		for(int i=0; i<k; i++) {
//			System.out.println("Key: " + keySet[i]);
//		}
//		testOB(500,m,k);
//                  attack3(100,m,k,k1,k2);
//                  attack2( 1000,  m,  k,  k1,  k2,  oba1,  oba2,  obb1,  obb2);
//                attack(1,m,k);
//                testInclusion(200,m,k);
//                Fenetre fen = new Fenetre();
                NewJFrame jframe= new NewJFrame();
//                testDisjointness(1, m, k);
//                testTime(1000,m,k);
//		BloomFilterHMAC bf1 = new BloomFilterHMAC(m, k, keySet);
//		BloomFilterHMAC bf2 = new BloomFilterHMAC(m, k, keySet);
//                
//                bf1.addMultiIP("255.148.200.0", "255.148.239.255");
//                bf2.addMultiIP("255.158.200.0", "255.158.239.255");
//                System.out.println("S: "+ disjointness(bf1, bf2) + " ");
//                System.out.println("sInter: "+ sInter(10239, 10239,k,m) + " ");
//                
//                bf2.add("255.148.201.0");
//                System.out.println("S: "+ disjointness(bf1, bf2) + " ");
//                System.out.println("sInter: "+ sInter(10239, 10240,k,m) + " ");
//                
//                
//                
//                BloomFilterHMAC bf3 = new BloomFilterHMAC(m, k, keySet);
//		BloomFilterHMAC bf4 = new BloomFilterHMAC(m, k, keySet);
//                
//                bf3.addMultiIP("254.148.200.0", "254.148.239.255");
//                bf4.addMultiIP("254.158.200.0", "254.158.239.255");
//                System.out.println("S: "+ disjointness(bf3, bf4) + " ");
//                System.out.println("sInter: "+ sInter(10239, 10239,k,m) + " ");
//                
//                bf4.add("254.148.201.0");
//                System.out.println("S: "+ disjointness(bf3, bf4) + " ");
//                System.out.println("sInter: "+ sInter(10239, 10240,k,m) + " ");
                
//		System.out.println(bf1.contains("255.148.201.48"));
//                System.out.println(bf1.contains("255.148.201.49"));
//                System.out.println(bf1.contains("255.148.201.50"));
//                System.out.println(bf1.contains("255.148.201.58"));
//                System.out.println(bf1.contains("255.148.201.59"));
                
//		bf1.add("255.255.248.105");
//		bf1.add("2");
//		bf1.add("3");
//		System.out.println("S: "+ disjointness(bf1, bf2) + " ");
//		System.out.println("sInter: "+ sInter(3, 0,k,m) + " ");
//		System.out.println(inclusion(bf1, bf2) + " ");
//		System.out.println(String.valueOf(255)+"."+String.valueOf(255)+"."+String.valueOf(248)+"."+String.valueOf(105));
//		bf2.add(String.valueOf(255)+"."+String.valueOf(255)+"."+String.valueOf(248)+"."+String.valueOf(105));
//		System.out.println("S: "+ disjointness(bf1, bf2) + " ");
//		System.out.println("sInter: "+ sInter(3, 1,k,m) + " ");
//		System.out.println(inclusion(bf1, bf2) + " ");
//		bf2.add("2");
//		System.out.println("S: "+ disjointness(bf1, bf2) + " ");
//		System.out.println("sInter: "+ sInter(3, 2,k,m) + " ");
//		System.out.println(inclusion(bf1, bf2) + " ");
//		bf2.add("3");
//		System.out.println("S: "+ disjointness(bf1, bf2) + " ");
//		System.out.println("sInter: "+ sInter(3, 3,k,m) + " ");
//		System.out.println(inclusion(bf1, bf2) + " ");

	}

}

