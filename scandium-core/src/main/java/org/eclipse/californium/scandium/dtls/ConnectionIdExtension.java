/*******************************************************************************
 * Copyright (c) 2019 Bosch Software Innovations GmbH and others.
 * 
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * and Eclipse Distribution License v1.0 which accompany this distribution.
 * 
 * The Eclipse Public License is available at
 *    http://www.eclipse.org/legal/epl-v10.html
 * and the Eclipse Distribution License is available at
 *    http://www.eclipse.org/org/documents/edl-v10.html.
 * 
 * Contributors:
 *    Bosch Software Innovations - initial creation
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;

import java.net.InetSocketAddress;

import org.eclipse.californium.elements.util.DatagramWriter;
import org.eclipse.californium.scandium.dtls.AlertMessage.AlertDescription;
import org.eclipse.californium.scandium.dtls.AlertMessage.AlertLevel;

/**
 * Conveys information specified by the <em>connection id</em> DTLS extension.
 * <p>
 * See <a href=
 * "https://datatracker.ietf.org/doc/draft-ietf-tls-dtls-connection-id">draft-ietf-tls-dtls-connection-id</a>
 * for additional details.
 *
 */
public final class ConnectionIdExtension extends HelloExtension {

	/**
	 * Number of bits for the encoded length of the connection id in the
	 * extension.
	 */
	private static final int CID_FIELD_LENGTH_BITS = 8;

	/**
	 * Connection id to negotiate.
	 */
	private ConnectionId id;

	/**
	 * Create connection id extension.
	 * 
	 * @param id connection id
	 */
	private ConnectionIdExtension(ConnectionId id) {
		super(ExtensionType.CONNECTION_ID);
		this.id = id;
	}

	/**
	 * Get connection id.
	 * 
	 * @return connection id
	 */
	public ConnectionId getConnectionId() {
		return id;
	}

	@Override
	public int getLength() {
		// 2 bytes indicating extension type, 2 bytes overall length,
		// 1 byte cid length + cid
		return 2 + 2 + 1 + id.length();
	}

	@Override
	protected void addExtensionData(final DatagramWriter writer) {
		int length = id.length();
		writer.write(1 + length, LENGTH_BITS);
		writer.write(length, CID_FIELD_LENGTH_BITS);
		writer.writeBytes(id.getBytes());
	}

	/**
	 * Create connection id extension from connection id.
	 * 
	 * @param cid connection id
	 * @return created connection id extension
	 * @throw NullPointerException if cid is {@code null}
	 */
	public static ConnectionIdExtension fromConnectionId(ConnectionId cid) {
		if (cid == null) {
			throw new NullPointerException("cid must not be null!");
		}
		return new ConnectionIdExtension(cid);
	}

	/**
	 * Create connection id extension from extensions data bytes.
	 * 
	 * @param extensionData extension data bytes
	 * @param peerAddress peer address
	 * @return created connection id extension
	 * @throw NullPointerException if extensionData is {@code null}
	 * @throws HandshakeException if the extension data could not be decoded
	 */
	public static ConnectionIdExtension fromExtensionData(final byte[] extensionData,
			final InetSocketAddress peerAddress) throws HandshakeException {
		if (extensionData == null) {
			throw new NullPointerException("cid must not be null!");
		} else if (extensionData.length == 0) {
			throw new HandshakeException("Connection id length must be provided!",
					new AlertMessage(AlertLevel.FATAL, AlertDescription.ILLEGAL_PARAMETER, peerAddress));
		} else if (extensionData.length > 256) {
			throw new HandshakeException(
					"Connection id length too large! 255 max, but has " + (extensionData.length - 1),
					new AlertMessage(AlertLevel.FATAL, AlertDescription.ILLEGAL_PARAMETER, peerAddress));
		}
		int len = extensionData[0];
		if (len != extensionData.length - 1) {
			throw new HandshakeException(
					"Connection id length " + len + " doesn't match " + (extensionData.length - 1) + "!",
					new AlertMessage(AlertLevel.FATAL, AlertDescription.ILLEGAL_PARAMETER, peerAddress));
		}
		if (len == 0) {
			return new ConnectionIdExtension(ConnectionId.EMPTY);
		} else {
			byte[] cid = new byte[len];
			System.arraycopy(extensionData, 1, cid, 0, len);
			return new ConnectionIdExtension(new ConnectionId(cid));
		}
	}

}
