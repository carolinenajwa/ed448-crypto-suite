import java.math.BigInteger;
/**
 * Represents a point on the Ed448 elliptic curve.
 * This class provides functionalities for elliptic curve operations such as addition,
 * scalar multiplication, and point negation.
 *
 * @author Andy Comfort
 * @author Caroline El Jazmi
 * @author Brandon Morgan
 */
public class Ed448Points {

    private BigInteger x;  // The x-coordinate of the point.
    private BigInteger y;  // The y-coordinate of the point.

    // The prime modulus of the curve equation.
//    private static final BigInteger SOLINAS_PRIME = BigInteger.valueOf(2).pow(448).subtract(BigInteger.TWO.pow(224)).subtract(BigInteger.ONE);
    private static final String HEX_VALUE = "fffffffffffffffffffffffffffffffffffffffffffffffffffffff"
            + "effffffffffffffffffffffffffffffffffffffffffffffffffffffff";
    private static final BigInteger SOLINAS_PRIME = new BigInteger(HEX_VALUE, 16);


    private static final BigInteger D = BigInteger.valueOf(-39081); // The value of 'd' for the curve

    // Constants for internal calculations
    private static final BigInteger ONE = BigInteger.ONE;
    private static final BigInteger ZERO = BigInteger.ZERO;


    /**
     * Constructor for the neutral element of the curve.
     * Initializes the point to (0, 1), which is the neutral element for addition on the curve.
     */
    public Ed448Points() {
        this.x = ZERO;
        this.y = ONE;
    }

    /**
     * Constructor for a curve point given x and y coordinates.
     * The coordinates are reduced modulo the curve's prime.
     *
     * @param x The x-coordinate of the point.
     * @param y The y-coordinate of the point.
     */
    public Ed448Points(BigInteger x, BigInteger y) {
        this.x = x.mod(SOLINAS_PRIME);
        this.y = y.mod(SOLINAS_PRIME);
    }
    /**
     * Constructor for a curve point from y-coordinate and the least significant bit of x.
     *
     * @param y The y-coordinate of the point.
     * @param lsbX The least significant bit of the x-coordinate.
     */
    public Ed448Points(BigInteger y, boolean lsbX) {
        this.x = calculateLeastSignX(y, lsbX);
        this.y = y;
    }

    /**
     * Creates and returns the public generator (base point) of the curve.
     *
     * @return The base point of the curve.
     */
    static Ed448Points getPublicGenerator(){
        return new Ed448Points(SOLINAS_PRIME.subtract(BigInteger.valueOf(3)), false);
    }

    /**
     * Calculates the least significant bit of the x-coordinate for a given y-coordinate.
     *
     * @param y The y-coordinate of the point.
     * @param xLsb The desired least significant bit of the x-coordinate.
     * @return The calculated x-coordinate.
     */
    static BigInteger calculateLeastSignX(BigInteger y, boolean xLsb) {
        // Compute x = ±√((1 − y^2)/(1 + 39081y^2)) mod p
        // Calculate y^2 mod p
        BigInteger ySquared = y.multiply(y).mod(SOLINAS_PRIME);

        // Calculate x^2 using the curve equation: x^2 = (1 - y^2) / (1 + dy^2)
        BigInteger xSquared = ONE.subtract(ySquared)
                .multiply(ONE.subtract(D.multiply(ySquared)).modInverse(SOLINAS_PRIME))
                .mod(SOLINAS_PRIME);
        
        return sqrt(xSquared, SOLINAS_PRIME, xLsb);
    }

    /**
     * Source: Paolo Barreto
     * Compute a square root of v mod p with a specified least-significant bit
     * if such a root exists.
     *
     * @param v the radicand.
     * @param p the modulus (must satisfy p mod 4 = 3).
     * @param lsb desired least significant bit (true: 1, false: 0).
     * @return a square root r of v mod p with r mod 2 = 1 iff lsb = true
     * if such a root exists, otherwise null.
     */
    public static BigInteger sqrt(BigInteger v, BigInteger p, boolean lsb) {
        assert (p.testBit(0) && p.testBit(1)); // p = 3 (mod 4)
        if (v.signum() == 0) {
            return BigInteger.ZERO;
        }
        BigInteger r = v.modPow(p.shiftRight(2).add(BigInteger.ONE), p);
        if (r.testBit(0) != lsb) {
            r = p.subtract(r); // correct the lsb
        }
        return (r.multiply(r).subtract(v).mod(p).signum() == 0) ? r : null;
    }
    /**
     * Performs scalar multiplication of a point on the curve.
     *
     * @param p The point to be multiplied.
     * @param s The scalar value for multiplication.
     * @return The result of the scalar multiplication.
     */
    public static Ed448Points scalarMultiply(Ed448Points p, BigInteger s) {
        Ed448Points r0 = new Ed448Points();
        Ed448Points r1 = new Ed448Points();
        r1.copy(p);

        String bitString = s.toString(2);
        int idx = bitString.length() - 1;

        while (idx >= 0) {
            if (bitString.charAt(idx--) == '1') {
                r0 = Ed448Points.summation(r0, r1);
                r1 = Ed448Points.doublePoint(r1);
            } else {
                r1 = Ed448Points.summation(r0, r1);
                r0 = Ed448Points.doublePoint(r0);
            }
        }

        return r0;
    }

    /**
     * Doubles a point on the curve.
     *
     * @param p The point to be doubled.
     * @return The doubled point.
     */
    public static Ed448Points doublePoint(Ed448Points p) {
        BigInteger x = p.x;
        BigInteger y = p.y;

        BigInteger xSquared = x.multiply(x).mod(SOLINAS_PRIME);
        BigInteger ySquared = y.multiply(y).mod(SOLINAS_PRIME);

        BigInteger xySquared = x.add(y).multiply(x.add(y)).mod(SOLINAS_PRIME);

        BigInteger denomDX = D.multiply(xSquared).multiply(ySquared);

        BigInteger newXNum = (xySquared.add(ySquared).add(xSquared)).multiply((BigInteger.ONE.add(denomDX)).modInverse(SOLINAS_PRIME));
        BigInteger newYNum = (xySquared.subtract(ySquared).subtract(xSquared)).multiply((BigInteger.ONE.subtract(denomDX).modInverse(SOLINAS_PRIME)));

        BigInteger newX = newXNum.mod(SOLINAS_PRIME);
        BigInteger newY = newYNum.mod(SOLINAS_PRIME);

        return new Ed448Points(newX, newY);
    }

    /**
     * Creates a copy of the given point.
     *
     * @param p The point to be copied.
     * @return A copy of the point.
     */
    public static Ed448Points copy(Ed448Points p) {
        return new Ed448Points(p.x, p.y);
    }
    
    /**
     * Performs the addition of two points on the curve.
     *
     * @param p1 The first point.
     * @param p2 The second point.
     * @return The sum of the two points.
     */
    public static Ed448Points summation(Ed448Points p1, Ed448Points p2) {
        BigInteger x1 = p1.x;
        BigInteger x2 = p2.x;
        BigInteger y1 = p1.y;
        BigInteger y2 = p2.y;

        BigInteger denomDX = D.multiply(x1).multiply(x2).multiply(y1).multiply(y2);

        BigInteger newXNum = (x1.multiply(y2)).add(y1.multiply(x2));
        BigInteger newX = (newXNum.multiply((BigInteger.ONE.add(denomDX)).modInverse(SOLINAS_PRIME)));

        BigInteger newYNum = ((y1.multiply(y2)).subtract(x1.multiply(x2)));
        BigInteger newY = newYNum.multiply((BigInteger.ONE.subtract(denomDX).modInverse(SOLINAS_PRIME)));

        newX = newX.mod(SOLINAS_PRIME);
        newY = newY.mod(SOLINAS_PRIME);

        return new Ed448Points(newX, newY);
    }

    /**
     * Compares this point with the specified object for equality.
     * The result is true if and only if the argument is not null and is an Ed448Points object that
     * represents the same point as this object. Two points are considered equal if their x and y
     * coordinates are the same.
     *
     * @param o The object to compare this Ed448Points against.
     * @return true if the given object represents an Ed448Points equivalent to this point, false otherwise.
     */
    @Override
    public boolean equals(Object o) {
        boolean result = false;
        if (o instanceof Ed448Points) {
            if (((Ed448Points) o).getX() == this.x && ((Ed448Points)o).getY() == this.y)  {
                result = true;
            }
        }
        return result;
    }

    /**
     * Gets the x-coordinate of the point.
     *
     * @return The x-coordinate.
     */
    public BigInteger getX() {
        return x;
    }
    /**
     * Gets the y-coordinate of the point.
     *
     * @return The y-coordinate.
     */
    public BigInteger getY() {
        return y;
    }
    /**
     * Gets the x-coordinate in byte array format.
     *
     * @return A byte array representing the x-coordinate.
     */
    public byte[] getXBytes() {
        return x.toByteArray();
    }
    /**
     * Gets the y-coordinate in byte array format.
     *
     * @return A byte array representing the y-coordinate.
     */
    public byte[] getYBytes() {
        return y.toByteArray();
    }
}



