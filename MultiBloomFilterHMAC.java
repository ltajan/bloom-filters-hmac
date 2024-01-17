import java.math.*;
import java.util.BitSet;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.util.Formatter;
import java.util.Random;




public class MultiBloomFilterHMAC {

	private BitSet[] storage;
    private int i;
	private int k;
	private String[] keySet;
	private BigInteger m;
    static BigInteger intMax= new BigInteger(Integer.toString(Integer.MAX_VALUE));

        
        /*  Constructor */
	public MultiBloomFilterHMAC(BigInteger m, int k, String keySet[]) {
            
                BigInteger temp= new BigInteger(m.toString());
                BigInteger intMax= new BigInteger(Integer.toString(Integer.MAX_VALUE));

                this.i=1;
                while(temp.compareTo(intMax)>0){
                        temp=temp.subtract(intMax);
                        i++;
                }
                System.out.println("# of BF: "+i);
                storage= new BitSet[i];
                storage[i-1]= new BitSet(temp.intValue());
                storage[i-1].clear();
                System.out.println("Size of BF["+(i-1)+"]: "+temp.intValue());
                
                for(int j = i-2; j>=0; j--){
                        storage[j]= new BitSet(Integer.MAX_VALUE);
                        storage[j].clear();
                        System.out.println("Here "+j);
                        System.out.println("Size of BF["+j+"]: "+Integer.MAX_VALUE);
                }
                    

		
		this.m = m;
		this.k = k;
		this.keySet = keySet;
		
	}
	/*  returns the HMAC value of item using key. */
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
        /*  adds the element item to the current Bloom filter */
	public void add(String item) {
                BigInteger intMax= new BigInteger(Integer.toString(Integer.MAX_VALUE));

		for(int i=0; i<k; i++) {
			BigInteger hmac_as_bigint = new BigInteger(hmac(item, keySet[i]), 16);
			hmac_as_bigint = hmac_as_bigint.mod(m);
			
//                        
//                        System.out.println("Which BF: "+temp);
//                        System.out.println("First index: "+index);
//                        System.out.println("Second index: "+(index-(temp* Integer.MAX_VALUE)));
			storage[hmac_as_bigint.divide(intMax).intValue()].set(hmac_as_bigint.remainder(intMax).intValue());
                        System.out.println("First index: "+hmac_as_bigint.divide(intMax).intValue());
                        System.out.println("Second index: "+hmac_as_bigint.remainder(intMax).intValue());
		}
	}

        /*  adds to the current Bloom filter the IP addresses range [start; end] */
	public void addMultiIP(String start, String end) {
//		System.out.println("start: "+ start);
//              System.out.println("end: "+ end);
                BigInteger intMax= new BigInteger(Integer.toString(Integer.MAX_VALUE));
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
                
//              System.out.println("start: "+ s1+"."+ s2+"."+ s3+"."+ s4);
//		System.out.println("end: "+ e1+"."+ e2+"."+ e3+"."+ e4);
//		System.out.println("s1: "+ s1 + " s2: "+ s2+" s3: "+ s3 +" s4: "+ s4);
                int addNbr= (e1-s1)*(256*256*256)+(e2-s2)*(256*256)+(e3-s3)*(256)+(e4-s4);
                
                for(int i=0; i<=addNbr; i++) {
                        for(int j=0; j<k; j++) {
                                BigInteger hmac_as_bigint = new BigInteger(hmac(String.valueOf((s1+(s2+((s3+(s4+i)/256)/256))/256)%256)+"."+String.valueOf((s2+((s3+(s4+i)/256)/256))%256)+"."+String.valueOf((s3+(s4+i)/256)%256)+"."+String.valueOf((s4+i)%256), keySet[j]), 16);
                                hmac_as_bigint = hmac_as_bigint.mod(m);
//                                System.out.println("Which BF: "+hmac_as_bigint.divide(intMax).intValue());
                                storage[hmac_as_bigint.divide(intMax).intValue()].set(hmac_as_bigint.remainder(intMax).intValue());
                        }
//              System.out.println(String.valueOf((s1+(s2+((s3+(s4+i)/256)/256))/256)%256)+"."+String.valueOf((s2+((s3+(s4+i)/256)/256))%256)+"."+String.valueOf((s3+(s4+i)/256)%256)+"."+String.valueOf((s4+i)%256));
                }
                System.out.println((addNbr+1)+ " IP address(es) have been added.");           
	}

        
        
        /*  adds to the current Bloom filter the IP addresses range [start; 
        start + n] */
	public void addAmountIP(String start, int n) {
                BigInteger intMax= new BigInteger(Integer.toString(Integer.MAX_VALUE));

		String [] startTab = start.split("\\.");
                
		int s1= Integer.parseInt(startTab[0]);
		int s2= Integer.parseInt(startTab[1]);
		int s3= Integer.parseInt(startTab[2]);
		int s4= Integer.parseInt(startTab[3]);
              
//              System.out.println("start: "+ s1+"."+ s2+"."+ s3+"."+ s4);
//		System.out.println("end: "+ e1+"."+ e2+"."+ e3+"."+ e4);
//		System.out.println("s1: "+ s1 + " s2: "+ s2+" s3: "+ s3 +" s4: "+ s4);
                int addNbr= n;
                
                for(int i=0; i<addNbr; i++) {
                        for(int j=0; j<k; j++) {
                            BigInteger hmac_as_bigint = new BigInteger(hmac(String.valueOf((s1+(s2+((s3+(s4+i)/256)/256))/256)%256)+"."+String.valueOf((s2+((s3+(s4+i)/256)/256))%256)+"."+String.valueOf((s3+(s4+i)/256)%256)+"."+String.valueOf((s4+i)%256), keySet[j]), 16);
                            hmac_as_bigint = hmac_as_bigint.mod(m);
                                                      
                            storage[hmac_as_bigint.divide(intMax).intValue()].set(hmac_as_bigint.remainder(intMax).intValue());
                        }
//                    System.out.println(String.valueOf((s1+(s2+((s3+(s4+i)/256)/256))/256)%256)+"."+String.valueOf((s2+((s3+(s4+i)/256)/256))%256)+"."+String.valueOf((s3+(s4+i)/256)%256)+"."+String.valueOf((s4+i)%256));
                }
	}



	/*  testes if the element item is already included in the current Bloom 
        filter. */
	public boolean contains(String item) {
            BigInteger intMax= new BigInteger(Integer.toString(Integer.MAX_VALUE));

		for(int i=0; i<k; i++) {
			BigInteger hmac_as_bigint = new BigInteger(hmac(item, keySet[i]), 16);
			hmac_as_bigint = hmac_as_bigint.mod(m);
                        			
			if(storage[hmac_as_bigint.divide(intMax).intValue()].get(hmac_as_bigint.remainder(intMax).intValue()) == false)
				return false;			
		}
		return true;
	}

        

        /*  returns true if the respective set of A is included in the 
        respective set of B and false otherwise. */
	public static boolean inclusion(MultiBloomFilterHMAC A, MultiBloomFilterHMAC B) {
		BigInteger intMax= new BigInteger(Integer.toString(Integer.MAX_VALUE));
                
                BitSet temp1= new BitSet(A.m.remainder(intMax).intValue());          
                BitSet temp2= new BitSet(Integer.MAX_VALUE);
                
                temp1.clear();
                temp1 = A.storage[A.i-1].get(0,A.m.remainder(intMax).intValue());
                temp1.flip(0, A.m.remainder(intMax).intValue());
                temp1.or(B.storage[A.i-1]);
                if (temp1.cardinality()!=A.m.remainder(intMax).intValue())
			return false;
                
                for(int j=0; j<A.i-1; j++){            
                        temp2.clear();
                        temp2 = A.storage[j].get(0,Integer.MAX_VALUE);
                        temp2.flip(0, Integer.MAX_VALUE);
                        temp2.or(B.storage[j]);
                        if (temp2.cardinality()!=Integer.MAX_VALUE)
                                return false;
                }
                return true;                
	}

        
        
        /*  returns the amount of bits set to one in the resulting Bloom filter 
        of (A AND B). */
	public static int disjointness(MultiBloomFilterHMAC A, MultiBloomFilterHMAC B) {
		
                BigInteger intMax= new BigInteger(Integer.toString(Integer.MAX_VALUE));

                BitSet temp1= new BitSet(A.m.remainder(intMax).intValue());          
                BitSet temp2= new BitSet(Integer.MAX_VALUE);
                int res=0;
                
                temp1.clear();
                temp1 = A.storage[A.i-1].get(0,A.m.remainder(intMax).intValue());
                temp1.and(B.storage[A.i-1]);
                res+=temp1.cardinality();

                for(int j=0; j<A.i-1; j++){            
                        temp2.clear();
                        temp2 = A.storage[j].get(0,Integer.MAX_VALUE);
                        temp2.and(B.storage[j]);
                        res+=temp2.cardinality();
                }
                return res;
	}

        
        
        
        /*  Constructor */
	public static float sInter(int n, int n2, int k, int m){
                
		return (float)n*n2*k*(k-1)/m;
	}
        
        
        
        /*  generates rounds times two Bloom filters and testes the disjointness
        function on them. */
        public static void testDisjointness (int rounds, BigInteger m, int k){
            
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
                BigInteger intMax= new BigInteger(Integer.toString(Integer.MAX_VALUE));
                int card=0;
                       
                for(int i=0; i<rounds; i++){         

                        String keySet[] = new String[k];
                        for(int j=0; j<k; j++) {
                                keySet[j] = "ok"+ rnd.nextInt(); //change this to something you want, maybe static keys? 
                        }

                        MultiBloomFilterHMAC bf1 = new MultiBloomFilterHMAC(m, k, keySet);
                        MultiBloomFilterHMAC bf2 = new MultiBloomFilterHMAC(m, k, keySet);
                        bf1.addMultiIP((10+(i/255))+"."+(i%255)+".200.0", (10+(i/255))+"."+(i%255)+".200.099");
                        bf2.addMultiIP((100+(i/255))+"."+(i%255)+".200.0", (100+(i/255))+"."+(i%255)+".203.231");

    //                  bf2.add((10+(i/255))+"."+(i%255)+".200.0");
    //                  bf2.add((10+(i/255))+"."+(i%255)+".200.1");
    //                  bf2.add((10+(i/255))+"."+(i%255)+".200.2");

    //                  bf2.add((100+i)+".148.201.0");
    //                  bf2.add((100+i)+".148.202.0");
                        S=disjointness(bf1, bf2);
                        System.out.println("S: "+ S + " ");
                        Smean=Smean+S;
                        if (S>Smax)
                                Smax=S;                
                        if (S<Smin)
                                Smin=S;
                        if (S<500)
                                res++;


                        BitSet temp1= new BitSet(m.remainder(intMax).intValue());          
                        BitSet temp2= new BitSet(Integer.MAX_VALUE);

                
                        temp1.clear();
                        temp1 = bf1.storage[bf1.i-1].get(0,m.remainder(intMax).intValue());
                        card+=temp1.cardinality();
                        

                        for(int j=0; j<bf1.i-1; j++){            
                                temp2.clear();
                                temp2 = bf1.storage[j].get(0,Integer.MAX_VALUE);
                                card+=temp2.cardinality();
                        }
                        System.out.println("#(1)="+card);

                        OA=(100*k)-card;
                        if (OA>OAmax)
                                OAmax=OA;                
                        if (OA<OAmin)
                                OAmin=OA;
                        System.out.println("# of overlapping="+OA);

                        temp1.clear();
                        card=0;
                        temp1 = bf2.storage[bf2.i-1].get(0,m.remainder(intMax).intValue());
                        card+=temp1.cardinality();
                        

                        for(int j=0; j<bf2.i-1; j++){            
                                temp2.clear();
                                temp2 = bf2.storage[j].get(0,Integer.MAX_VALUE);
                                card+=temp2.cardinality();
                        }

                        System.out.println("#(1)="+card);
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
        
        
        
        /*  generates rounds times two Bloom filters and testes the inclusion 
        function on them. */
        public static void testInclusion (int rounds, BigInteger m, int k){
            
                Random rnd = new Random();
                int res=0;
                int S;
                int Smax=0;

                for(int i=0; i<rounds; i++){         

                        String keySet[] = new String[k];
                        for(int j=0; j<k; j++) {
                                keySet[j] = "ok"+ rnd.nextInt(); //change this to something you want, maybe static keys? 
                        }

                        MultiBloomFilterHMAC bf1 = new MultiBloomFilterHMAC(m, k, keySet);
                        MultiBloomFilterHMAC bf2 = new MultiBloomFilterHMAC(m, k, keySet);
                        bf1.addMultiIP((100+(i/255))+"."+(i%255)+".200.0", (100+(i/255))+"."+(i%255)+".203.231");
                        bf2.addMultiIP((100+(i/255))+"."+(i%255)+".200.0", (100+(i/255))+"."+(i%255)+".203.230");

                        bf2.add((10+(i/255))+"."+(i%255)+".200.0");

                        System.out.println(i);
                        System.out.println(inclusion(bf1,bf2));

                        if(inclusion(bf1, bf2))
                                res++;     
                }

                System.out.println("Inclusion: "+res+" errors.");     
        }
        
        
        
        /*  gives the average times of computation of function inclusion or 
        disjointness. */
        public static void testTime (int rounds, BigInteger m, int k){
            
                Random rnd = new Random();
                int res=0;
                int S;
                int Smax=0;
            
                String keySet[] = new String[k];
                for(int j=0; j<k; j++) {
			keySet[j] = "ok"+ rnd.nextInt(); //change this to something you want, maybe static keys? 
                }
            
                MultiBloomFilterHMAC bf1 = new MultiBloomFilterHMAC(m, k, keySet);
                MultiBloomFilterHMAC bf2 = new MultiBloomFilterHMAC(m, k, keySet);
                bf1.addMultiIP("148.148.200.0", "148.148.203.231");
                bf2.addMultiIP("148.149.200.0", "148.149.203.231");
            
                long startTime = System.nanoTime();        
                for(int i=0; i<rounds; i++){                        
//                  disjointness(bf1, bf2);
                    inclusion(bf1, bf2);      
                }
                long stopTime = System.nanoTime();
                long elapsedTime = stopTime - startTime;
                elapsedTime = elapsedTime/ rounds;
                System.out.println(elapsedTime);
        }
        
        
        
        /*  performs the attack in the Best Case. */
        public static void attack1 (int rounds, BigInteger m, int k){
            
                Random rnd = new Random();
                int res=0;
                int S;
                int Smax=0;
                int card=0;
                       
                for(int i=0; i<rounds; i++){         
                        String keySet[] = new String[k];
                        for(int j=0; j<k; j++) {
                                keySet[j] = "ok"+ rnd.nextInt(); //change this to something you want, maybe static keys? 
                        }
                
                        MultiBloomFilterHMAC bf1 = new MultiBloomFilterHMAC(m, k, keySet);
                        MultiBloomFilterHMAC bf2 = new MultiBloomFilterHMAC(m, k, keySet);
                        bf1.addMultiIP((100+i)+".148.200.0", (100+i)+".148.201.215");
                        bf2.addMultiIP((100+i)+".158.200.0", (100+i)+".158.202.108");                        
//                      bf1.add((100+i)+".149.200.0");

                        BitSet temp1= new BitSet(m.remainder(intMax).intValue());          
                        BitSet temp2= new BitSet(Integer.MAX_VALUE);

                
                        temp1.clear();
                        temp1 = bf1.storage[bf1.i-1].get(0,m.remainder(intMax).intValue());
                        card+=temp1.cardinality();
                        

                        for(int j=0; j<bf1.i-1; j++){            
                                temp2.clear();
                                temp2 = bf1.storage[j].get(0,Integer.MAX_VALUE);
                                card+=temp2.cardinality();
                        }

                
                        System.out.println("#(1)="+card);
                        System.out.println("# of overlapping="+((1024*k)-card));
 
                        
                        temp1.clear();
                        card=0;
                        temp1 = bf2.storage[bf2.i-1].get(0,m.remainder(intMax).intValue());
                        card+=temp1.cardinality();
                        

                        for(int j=0; j<bf2.i-1; j++){            
                                temp2.clear();
                                temp2 = bf2.storage[j].get(0,Integer.MAX_VALUE);
                                card+=temp2.cardinality();
                        }
                        
                
                        System.out.println("#(1)="+card);
                        System.out.println("# of overlapping="+((2305*k)-card));                 
                }
//              float resF=res*100/rounds;
//              System.out.println("Inclusion: "+res+" errors.");
//              System.out.println("S max: "+Smax);  
        }
        
        
        
        /*  gives the average amount of overlapping bits when generating rounds 
        times a Bloom filter. */
        public static void testOB (int rounds, BigInteger m, int k){
            
                Random rnd = new Random();
                int res=0;
                int S;
                int Smax=0;
                int [] tab= new int[1000];
                int t=0;
                int tmax=0;
                int tmin=10000;
                int card=0;
                       
                for(int i=0; i<rounds; i++){          
                        String keySet[] = new String[k];
                        for(int j=0; j<k; j++) {
                                keySet[j] = "ok"+ rnd.nextInt(); //change this to something you want, maybe static keys? 
                        }
                
                        MultiBloomFilterHMAC bf1 = new MultiBloomFilterHMAC(m, k, keySet);
                        bf1.addMultiIP((100+i)+".148.200.0", (100+i)+".148.203.231");
                
                        BitSet temp1= new BitSet(m.remainder(intMax).intValue());          
                        BitSet temp2= new BitSet(Integer.MAX_VALUE);

                
                        temp1.clear();
                        temp1 = bf1.storage[bf1.i-1].get(0,m.remainder(intMax).intValue());
                        card+=temp1.cardinality();
                        

                        for(int j=0; j<bf1.i-1; j++){            
                                temp2.clear();
                                temp2 = bf1.storage[j].get(0,Integer.MAX_VALUE);
                                card+=temp2.cardinality();
                        }
                        
                        t=(1000*k)-card;
                        tab[t]++;
                        if (t>tmax)
                                tmax=t;                
                        if (t<tmin)
                                tmin=t;
                        System.out.println("# of overlapping="+((1000*k)-card));                                  
                }
                for(int i=tmin; i<tmax+1;i++){
                        System.out.println("tab["+i+"]: "+tab[i]);     
                }
//            float resF=res*100/rounds;
//            System.out.println("Inclusion: "+res+" errors.");
//            System.out.println("S max: "+Smax);          
        }
        
        
//        
//        /*  gives the average amount of the overlapping bits and its respective 
//        standard deviation when generating rounds times two Bloom filters and 
//        the resulting Bloom filter from the disjointness operator on the two 
//        Bloom filters. */
//        public static void testOB2 (int rounds, int m, int k){
//            
//                Random rnd = new Random();
//                int n=1000;
//                int nP=1000;
//                int res=0;
//                int [] tabS= new int[100000];
//                int S=0;
//                int Smax=0;
//                int Smin=10000;
//                int [] tab1= new int[1000000];
//                int t1=0;
//                int t1max=0;
//                int t1min=10000;
//                double t1moy=0;
//                double s1=0;
//                int [] tab2= new int[1000000];
//                int t2=0;
//                int t2max=0;
//                int t2min=10000;
//                double t2moy=0;
//                double Smoy=0;
//                double s2=0;
//                double s3=0;
//                       
//                for(int i=0; i<rounds; i++){         
//                
//                        String keySet[] = new String[k];
//                        for(int j=0; j<k; j++) {
//                                keySet[j] = "ok"+ rnd.nextInt(); //change this to something you want, maybe static keys? 
//                        }
//
//                        MultiBloomFilterHMAC bf1 = new MultiBloomFilterHMAC(m, k, keySet);
//                        MultiBloomFilterHMAC bf2 = new MultiBloomFilterHMAC(m, k, keySet);
//
//                        bf1.addMultiIP((10+(i/255))+"."+(i%255)+".200.0", (10+(i/255))+"."+(i%255)+".203.231");
//                        bf2.addMultiIP((100+(i/255))+"."+(i%255)+".200.0", (100+(i/255))+"."+(i%255)+".203.231");
//
//                        S=disjointness(bf1, bf2);
//                        tabS[S]++;
//                        if (S>Smax)
//                                Smax=S;                
//                        if (S<Smin)
//                                Smin=S;                
//                        BitSet temp1= new BitSet(bf1.m.intValue());
//                        temp1 = bf1.storage.get(0,bf1.m.intValue());
//                        t1=(n*k)-temp1.cardinality();
//                        tab1[t1]++;
//                        if (t1>t1max)
//                                t1max=t1;                
//                        if (t1<t1min)
//                                t1min=t1;
//
//                        BitSet temp2= new BitSet(bf2.m.intValue());
//                        temp2 = bf2.storage.get(0,bf2.m.intValue());
//                        t2=(nP*k)-temp2.cardinality();
//                        tab2[t2]++;
//                        if (t2>t2max)
//                                t2max=t2;                
//                        if (t2<t2min)
//                                t2min=t2;   
//
//        //               System.out.println("#(1)="+temp.cardinality());
//        //               System.out.println("# of overlapping="+((100*k)-temp.cardinality()));                          
//                        if(inclusion(bf1, bf2))
//                                res++;                
//                }
//
//                for(int i=t1min; i<t1max+1;i++){
//                        t1moy=t1moy+(tab1[i]*i);
//                } 
//                t1moy=t1moy/rounds;
//                System.out.println("moyenne: "+t1moy); 
//                
//                System.out.println("tab1"); 
//                for(int i=t1min; i<t1max+1;i++){
//                        System.out.println("("+i+","+tab1[i]/10.0+")");
//                        for(int j=0; j<tab1[i];j++){
//                                s1=s1+Math.pow((i-t1moy),2);
//                        }
//                }
//                s1=s1/rounds;
//                s1= Math.sqrt(s1);
//                System.out.println("stand dev: "+s1);
//           
//                for(int i=t2min; i<t2max+1;i++){
//                        t2moy=t2moy+(tab2[i]*i);
//                } 
//                t2moy=t2moy/rounds;
//                System.out.println("moyenne: "+t2moy);
//            
//                System.out.println("tab2"); 
//                for(int i=t2min; i<t2max+1;i++){
//                        System.out.println("("+i+","+tab2[i]/10.0+")");      
//                        for(int j=0; j<tab2[i];j++){
//                                s2=s2+Math.pow((i-t2moy),2);
//                        }
//                }
//                s2=s2/rounds;
//                s2= Math.sqrt(s2);
//                System.out.println("stand dev: "+s2);
//
//                for(int i=Smin; i<Smax+1;i++){
//                        Smoy=Smoy+(tabS[i]*i);
//                } 
//                Smoy=Smoy/rounds;
//                System.out.println("moyenne: "+Smoy);
// 
//                System.out.println("tabS"); 
//                for(int i=Smin; i<Smax+1;i++){
//                        System.out.println("("+i+","+tabS[i]/1000.0+")"); 
//                        for(int j=0; j<tabS[i];j++){
//                                s3=s3+Math.pow((i-Smoy),2);
//                        }
//                }
//            
//                s3=s3/rounds;
//                s3= Math.sqrt(s3);
//                System.out.println("stand dev: "+s3);
//
//                float resF=res*100/rounds;
//                System.out.println("Inclusion: "+res+" errors.");
//                System.out.println("S max: "+Smax);             
//        }
//        
//        
//        
//        /*  performs the attack in the In-between Case. */
//        public static void attack2(int rounds, int m, int k, int k1, int k2, int oba1, int oba2, int obb1, int obb2){
//            
//                Random rnd = new Random(); 
//                int[] L= new int[k2+1];
//                int[] L1= new int[k2-k1+1];
//                int[] L2= new int[k2-k1+1];
//                int t1;
//                int t2;
//
//                String keySet[] = new String[k];
//                for(int j=0; j<k; j++) {
//                        keySet[j] = "ok"+ rnd.nextInt(); //change this to something you want, maybe static keys? 
//                }
//                
//                MultiBloomFilterHMAC bf1 = new MultiBloomFilterHMAC(m, k, keySet);
//                MultiBloomFilterHMAC bf2 = new MultiBloomFilterHMAC(m, k, keySet);
//                bf1.addMultiIP("100.148.200.0", "100.148.200.099"); /*100 IP  */
////              bf2.addMultiIP("100.158.200.0", "100.158.203.231"); /*1000 IP  */
////              bf1.addMultiIP("100.148.200.0", "100.148.200.009"); /*10 IP  */
//                bf2.addMultiIP("100.158.200.0", "100.158.200.099");  /*100 IP  */
//            
//                BitSet temp1= new BitSet(bf1.m.intValue());
//                temp1 = bf1.storage.get(0,bf1.m.intValue());
//                t1=temp1.cardinality();
//
//                BitSet temp2= new BitSet(bf2.m.intValue());
//                temp2 = bf2.storage.get(0,bf2.m.intValue());
//                t2=temp2.cardinality();
//
//                System.out.println("#1 in BFA: "+t1);
//                System.out.println("#1 in BFB: "+t2);
//                       
//                for (int i=oba1; i<= oba2; i++){      
//                        for (int j=k1; j<=k2; j++){
//                                if((t1+i)%j==0)
//                                L1[(j-k1)]++;
//                        }
//                }
//            
//                for (int i=obb1; i<= obb2; i++){      
//                        for (int j=k1; j<=k2; j++){
//                                if((t2+i)%j==0)
//                                L2[(j-k1)]++;
//                        }
//                }
//                        
//                for (int i=k1; i<= k2; i++){
//                        if((L1[i-k1]*L2[i-k1])>0)
//                        L[i]++;
//                }
//            
//                System.out.println("lambda_A: "+lambda(L1));
//                System.out.println("lambda_B: "+lambda(L2));
//                System.out.println("lambda: "+lambda(L));
//                System.out.println("lambda: "+lambdaPrint(L, k1));
//        }
//             
//        
//        
//        /*  performs the attack in the Worst Case. */
//        public static void attack3(float rounds, int m, int k, int k1, int k2){
//            
//                Random rnd = new Random();            
//                int n=100;
//                int nP=1000;
//                int res=0;
//                int [] tabS= new int[100000];
//                int S=0;
//                int Smax=0;
//                int Smin=10000;
//                double [] tab1= new double[1000000];
//                int t1=0;
//                int t1max=0;
//                int t1min=10000;
//                double t1moy=0;
//                double s1=0;
//                double [] tab2= new double[1000000];
//                int t2=0;
//                int t2max=0;
//                int t2min=10000;
//                double t2moy=0;
//                double s2=0;
//                 
//                for(int i=0; i<rounds; i++){         
//
//                        String keySet[] = new String[k];
//                        for(int j=0; j<k; j++) {
//                                keySet[j] = "ok"+ rnd.nextInt(); //change this to something you want, maybe static keys? 
//                        }
//
//                        MultiBloomFilterHMAC bf1 = new MultiBloomFilterHMAC(m, k, keySet);
//                        MultiBloomFilterHMAC bf2 = new MultiBloomFilterHMAC(m, k, keySet);
//                        System.out.println("Round "+(i+1)+":");
//                        bf1.addMultiIP((100+i)+".148.200.0", (100+i)+".148.200.099");
//                        bf2.addMultiIP((100+i)+".158.200.0", (100+i)+".158.203.231");
//
//                        BitSet temp1= new BitSet(bf1.m.intValue());
//                        temp1 = bf1.storage.get(0,bf1.m.intValue());
//                        t1=(n*k)-temp1.cardinality();
//                        tab1[t1]++;
//                        if (t1>t1max)
//                                t1max=t1;                
//                        if (t1<t1min)
//                                t1min=t1;
//
//                        BitSet temp2= new BitSet(bf2.m.intValue());
//                        temp2 = bf2.storage.get(0,bf2.m.intValue());
//                        t2=(nP*k)-temp2.cardinality();
//                        tab2[t2]++;
//                        if (t2>t2max)
//                                t2max=t2;                
//                        if (t2<t2min)
//                                t2min=t2;                                           
//                }
//                                   
//                System.out.println("tab1");
//                System.out.println("t1min: "+t1min);
//                System.out.println("t1max: "+t1max); 
//                for(int i=t1min; i<t1max+1;i++){
//                        System.out.println("("+i+","+tab1[i]/rounds*100+")");
//                        tab1[i]=tab1[i]+0.1;
//                }         
//                System.out.println("tab2");
//                System.out.println("t2min: "+t2min);
//                System.out.println("t2max: "+t2max); 
//                for(int i=t2min; i<t2max+1;i++){
//                        System.out.println("("+i+","+tab2[i]/rounds*100+")");
//                        tab2[i]=tab2[i]+0.1;
//                }
//
//                double[] L= new double[k2+1];
//                double[] L1= new double[k2-k1+1];
//                double[] L2= new double[k2-k1+1];
//                int X1;
//                int X2;
//
//                String keySet[] = new String[k];
//                for(int j=0; j<k; j++) {
//                    keySet[j] = "ok"+ rnd.nextInt(); //change this to something you want, maybe static keys? 
//                }
//            
//                MultiBloomFilterHMAC bf1 = new MultiBloomFilterHMAC(m, k, keySet);
//                MultiBloomFilterHMAC bf2 = new MultiBloomFilterHMAC(m, k, keySet);
//                bf1.addMultiIP("100.148.200.0", "100.148.200.099"); /*100 IP  */
//                bf2.addMultiIP("100.158.200.0", "100.158.203.231"); /*1000 IP  */           
//
//                BitSet temp1= new BitSet(bf1.m.intValue());
//                temp1 = bf1.storage.get(0,bf1.m.intValue());
//                X1=temp1.cardinality();
//
//                BitSet temp2= new BitSet(bf2.m.intValue());
//                temp2 = bf2.storage.get(0,bf2.m.intValue());
//                X2=temp2.cardinality();
//
//                System.out.println("#1 in BFA: "+X1);
//                System.out.println("#1 in BFB: "+X2);
//
//                for (int i=t1min; i<=t1max; i++){      
//                        for (int j=k1; j<=k2; j++){
//                                if((X1+i)%j==0)
//                                        L1[(j-k1)]=tab1[i];
//                        }
//                }
//            
//                for (int i=t2min; i<= t2max; i++){      
//                        for (int j=k1; j<=k2; j++){
//                                if((X2+i)%j==0)
//                                        L2[(j-k1)]=tab2[i];
//                        }
//                }
//
//                double maxWeight=0.0;
//                for (int i=k1; i<= k2; i++){
//                        if((L1[i-k1]*L2[i-k1])>0)
//                        L[i]=L1[i-k1]+L2[i-k1];
//                        if(maxWeight<L[i])
//                                maxWeight=L[i];
//                }
//
//                for (int i=k1; i<=k2; i++)
//                        L[i]=L[i]/maxWeight;
//
//                System.out.println("lambda: "+lambdaPrintDouble(L, k1)); 
//        }
//        
//        
        
        /*  Constructor */
        public static int lambda(int [] L){
            
                int res=0;
                for(int i=0; i<L.length;i++){
                        if(L[i]==1)
                                res++;
                }
                return res;
        }
        
        
        
        /*  Constructor */
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
        
        
        
        /*  Constructor */
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
        
        
        
        /*  determines the smaller acceptable parameter m. */
        public static String setm(int nkey, int nw, int nL2, int nkeyL){
                
                double m =100000;
                double x;
            
                x= m * (1-Math.pow((1-(1/m)),(nkey*nw))) * (1-Math.pow((1-(1/m)),(nkey*nL2)));

                while((1.1*x)>nkeyL){
                        m+=100;
                        x= m * (1-Math.pow((1-(1/m)),(nkey*nw))) * (1-Math.pow((1-(1/m)),(nkey*nL2)));
                }
                String test = String.format("%.0f", m);
                System.out.println("m: " + test);
                return test;          
        }
             
        
        
        /*  randomly generates parameter n key in range [nkeyL; nkeyU]. */
        public static int setnkey(int nkeyL, int nkeyU){
            
                int nkey;
                Random rndnkey =new Random();
                nkey= rndnkey.nextInt((nkeyU-nkeyL)+1) + nkeyL;
                System.out.println("nkey: "+nkey);

                return nkey;
        }
        
        
        
        /*  generates the Bloom filters with the sizes from inputs and performs 
        the audit protocols on them. Finally it returns a table a values that 
        represent the generated parameters, the percentage of errors and the 
        computation times of the functions. */
        public static double [] completeProtocol(int nw, int nL1, int ZL1w, int nL2, int ZprimeL2w, int rounds){
            
                double [] res= new double[9];
                Random rnd = new Random();
                int nkeyL= 500;
                int nkeyU= 2000;
                int nkey;
                BigInteger m;
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

                m= new BigInteger(setm(nkey, nw, nL2, nkeyL));
                                  
                for(int i=0; i<rounds; i++){
                        System.out.println("i: "+i);
                        
                        /*    Keys Generation    */
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
                        MultiBloomFilterHMAC bfw = new MultiBloomFilterHMAC(m, nkey, keySet);
                        MultiBloomFilterHMAC bfL1 = new MultiBloomFilterHMAC(m, nkey, keySet);
                        MultiBloomFilterHMAC bfL2 = new MultiBloomFilterHMAC(m, nkey, keySet);

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
                
                res[0]=nkey;
                res[1]=m.doubleValue();
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
		BigInteger m = new BigInteger ("3147483647");
//              int m= 60000000;
//		int k = 500;
//              int k1=50;
//              int k2=5000;
//              int oba1=500;
//              int oba2=1000;
//              int obb1=500;
//              int obb2=1000;

//                NewJFrame jframe= new NewJFrame();
                Random rnd = new Random();

                int nkey=10;

                String keySet[] = new String[nkey];
                for(int j=0; j<nkey; j++) {
                        keySet[j] = "ok"+ rnd.nextInt(); //change this to something you want, maybe static keys? 
                }


                MultiBloomFilterHMAC bfw = new MultiBloomFilterHMAC(m, nkey, keySet);
                MultiBloomFilterHMAC bfL1 = new MultiBloomFilterHMAC(m, nkey, keySet);
                MultiBloomFilterHMAC bfL2 = new MultiBloomFilterHMAC(m, nkey, keySet);

//                bfL1.add("100.148.200.0");
                bfL1.addMultiIP("100.148.200.0", "100.148.200.99"); /*100 IP  */
//                bfL2.addMultiIP("100.148.200.0", "100.148.200.099"); /*100 IP  */
                bfL2.addMultiIP("100.148.200.0", "100.148.203.231"); /*1000 IP  */


                if(bfL1.contains("100.148.200.99"))
                        System.out.println("OK");
                else System.out.println("Non Lourd");

                if(inclusion(bfL1,bfL2))
                        System.out.println("Included");
                else System.out.println("Not Included");

                System.out.println("Disjointness: "+disjointness(bfL1, bfL2));
                completeProtocol(1000,1000,0,1000,0,1);
	}
}