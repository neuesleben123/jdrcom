import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.nio.ByteBuffer;
import java.security.NoSuchAlgorithmException;

import jpcap.packet.DatalinkPacket;
import jpcap.packet.EthernetPacket;
import jpcap.packet.Packet;

public final class _802dot1XPacket extends Packet {

	private static final long serialVersionUID = -7488671391679694859L;

	{
		// static byte[] trailer1 = { (byte) 0xff, (byte) 0xff, (byte) 0x37,
		// (byte) 0x77, (byte) 0x7f, (byte) 0xff, (byte) 0xff, (byte) 0xff,
		// (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
		// (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
		// (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xf5, (byte) 0x71,
		// (byte) 0x00, (byte) 0x00, (byte) 0x13, (byte) 0x11, (byte) 0x38,
		// (byte) 0x30, (byte) 0x32, (byte) 0x31, (byte) 0x78, (byte) 0x2e,
		// (byte) 0x65, (byte) 0x78, (byte) 0x65, (byte) 0x00, (byte) 0x00,
		// (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
		// (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
		// (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
		// (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
		// (byte) 0x00, (byte) 0x02, (byte) 0x32, (byte) 0x00, (byte) 0x00,
		// (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x13, (byte) 0x11,
		// (byte) 0x00, (byte) 0x28, (byte) 0x1a, (byte) 0x28, (byte) 0x00,
		// (byte) 0x00, (byte) 0x13, (byte) 0x11, (byte) 0x17, (byte) 0x22,
		// (byte) 0x92, (byte) 0x68, (byte) 0x64, (byte) 0x66, (byte) 0x92,
		// (byte) 0x94, (byte) 0x62, (byte) 0x66, (byte) 0x91, (byte) 0x93,
		// (byte) 0x95, (byte) 0x62, (byte) 0x93, (byte) 0x93, (byte) 0x91,
		// (byte) 0x94, (byte) 0x64, (byte) 0x61, (byte) 0x64, (byte) 0x64,
		// (byte) 0x65, (byte) 0x66, (byte) 0x68, (byte) 0x94, (byte) 0x98,
		// (byte) 0xa7, (byte) 0x61, (byte) 0x67, (byte) 0x65, (byte) 0x67,
		// (byte) 0X9c, (byte) 0x6b };
		// static byte[] trailer2 = { (byte) 0x00, (byte) 0x00, (byte) 0x13,
		// (byte) 0x11, (byte) 0x18, (byte) 0x06, (byte) 0x00, (byte) 0x00,
		// (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
		// (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
		// (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
		// (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
		// (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
		// (byte) 0x00, (byte) 0x00, (byte) 0x00 };
		// static byte[] trailer3 = { (byte) 0x00, (byte) 0x00, (byte) 0x2f,
		// (byte) 0xfc, (byte) 0x02, (byte) 0x06, (byte) 0x00, (byte) 0x00,
		// (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
		// (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
		// (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
		// (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
		// (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
		// (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
		// (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00 };
	}
	public static final byte EAPOL_TYPE_EAPPACKET = 0;
	public static final byte EAPOL_TYPE_START = 1;
	public static final byte EAPOL_TYPE_LOGOFF = 2;

	public static final byte EAP_CODE_REQUEST = 0x01;
	public static final byte EAP_CODE_RESPONSE = 0x02;
	public static final byte EAP_CODE_SUCCESS = 0x03;
	public static final byte EAP_CODE_FAILURE = 0x04;

	public static final byte EAP_REQUEST_IDENTITY = 0x01;
	public static final byte EAP_REQUEST_NOTIFICATION = 0x02;
	public static final byte EAP_REQUEST_MD5_CHALLENGE = 0x04;

	public static final short ETHERTYPE_802DOT1X = (short) 0x888e;

	private EthernetPacket ep = new EthernetPacket();
	public static final byte[] Nearest_mac = new byte[] { 0x01, (byte) 0x80,
			(byte) 0xc2, 0x00, 0x00, 0x03 };

	public byte Version = 1;
	public byte Type;
	public short Lenght = 0;

	public _802dot1XPacket(byte eapolType, byte eapType) {
		// TODO Auto-generated constructor stub
		this(new byte[6], eapolType);
		if (eapolType == EAPOL_TYPE_EAPPACKET) {
			setEAPCode(eapType);
		}
		data = new byte[60];
	}

	public _802dot1XPacket(byte[] src_mac, byte eapolType) { // Start
		ep.frametype = ETHERTYPE_802DOT1X;
		this.datalink = ep;
		ep.src_mac = src_mac.clone();
		ep.dst_mac = Nearest_mac;

		ByteBuffer buf = ByteBuffer.wrap(new byte[84]);
		buf.put(Version);
		buf.put(eapolType);
		buf.putShort(Lenght);

		this.data = buf.array();
		return;
	}

	public _802dot1XPacket(Packet p) { // ConvertTo802dot1XPacket
		this.datalink = (DatalinkPacket) SerialClone(p.datalink);
		this.data = p.data.clone();
	}

	public byte getEAPOLType() {
		if (((EthernetPacket) this.datalink).frametype == ETHERTYPE_802DOT1X)
			return data[1];
		return 0; // Not a EAPOLType
	}

	public boolean setEAPOLLenght(short lenght) {
		try {
			data[2] = (byte) ((lenght >> 8) & 0xff);
			data[3] = (byte) (lenght & 0xff);
		} catch (ArrayIndexOutOfBoundsException e) {
			return false;
		}
		return true;
	}

	public byte getEAPCode() {
		return data[4];
	}
	public boolean setEAPCode(byte eapType) {
		try {
			data[4] = eapType;
		} catch (ArrayIndexOutOfBoundsException e) {
			return false;
		}
		return true;
	}

	public byte getEAPType() {
		return data[8];
	}

	public boolean setEAPLenght(short lenght) {
		try {
			data[6] = (byte) ((lenght >> 8) & 0xff);
			data[7] = (byte) (lenght & 0xff);
		} catch (ArrayIndexOutOfBoundsException e) {
			return false;
		}
		return true;
	}

	public boolean setEAPIdentity(byte[] Identity) {
		try {
			System.arraycopy(Identity, 0, data, 9, Identity.length);
		} catch (ArrayIndexOutOfBoundsException e) {
			return false;
		}
		return true;
	}

	public byte[] getEAPValue() {
		byte[] value = new byte[16];
		System.arraycopy(data, 10, value, 0, 16);
		return value;
	}
	
	public boolean setEAPValue(byte[] md5) {
		try {
			System.arraycopy(md5, 0, data, 10, md5.length);
		} catch (ArrayIndexOutOfBoundsException e) {
			return false;
		}
		return true;
	}
	
	public boolean setEAPExtra(byte[] Extra) {
		try {
			System.arraycopy(Extra, 0, data, 26, Extra.length);
		} catch (ArrayIndexOutOfBoundsException e) {
			return false;
		}
		return true;
	}


	public boolean ConvertToIdentityResponse(String UserName, byte[] src_mac) {
		if (getEAPOLType() == EAPOL_TYPE_EAPPACKET
				&& getEAPCode() == EAP_CODE_REQUEST
				&& getEAPType() == EAP_REQUEST_IDENTITY) {
			byte[] newdata = new byte[82];
			System.arraycopy(data, 0, newdata, 0, data.length);
			data = newdata;
			((EthernetPacket) this.datalink).src_mac = src_mac.clone();
			setEAPOLLenght((short) (5 + UserName.length()));
			setEAPCode(EAP_CODE_RESPONSE);
			setEAPLenght((short) (5 + UserName.length()));
			setEAPIdentity(UserName.getBytes().clone());
			return true;
		}
		return false;
	}

	public boolean ConvertToMD5ChallengeResponse(String UserName,
			String Password, byte[] src_mac) {
		if (getEAPOLType() == EAPOL_TYPE_EAPPACKET
				&& getEAPCode() == EAP_CODE_REQUEST
				&& getEAPType() == EAP_REQUEST_MD5_CHALLENGE) {
			byte[] newdata = new byte[82];
			System.arraycopy(data, 0, newdata, 0, data.length);
			data = newdata;
			((EthernetPacket) this.datalink).src_mac = src_mac;
			setEAPOLLenght((short) (22 + UserName.length()));
			setEAPCode(EAP_CODE_RESPONSE);
			setEAPLenght((short) (22 + UserName.length()));

			java.security.MessageDigest digest;
			try {
				digest = java.security.MessageDigest.getInstance("MD5");
				byte[] pwd = new byte[1 + Password.length() + 16];
				System.arraycopy(Password.getBytes(), 0, pwd, 1, Password
						.getBytes().length);
				System.arraycopy(getEAPValue(), 0, pwd,
						1 + Password.getBytes().length, 16);
				digest.update(pwd);
				setEAPValue(digest.digest());
				setEAPExtra(UserName.getBytes());
			} catch (NoSuchAlgorithmException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}

			return true;
		}
		return false;
	}

	private Object SerialClone(Object srcobj) {
		try {
			ByteArrayOutputStream byteOut = new ByteArrayOutputStream();
			ObjectOutputStream out = new ObjectOutputStream(byteOut);
			out.writeObject(srcobj);
			ByteArrayInputStream byteIn = new ByteArrayInputStream(byteOut
					.toByteArray());
			ObjectInputStream in = new ObjectInputStream(byteIn);
			Object dstobj = in.readObject();
			return dstobj;

		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return null;
		} catch (ClassNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return null;
		}
	}
}
