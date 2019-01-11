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
 *    Bosch Software Innovations GmbH - initial API and implementation
 *******************************************************************************/
package org.eclipse.californium.scandium.dtls;

import java.util.ArrayList;
import java.util.List;

import org.eclipse.californium.elements.util.StringUtil;

/**
 * Reassemble fragmented handshake messages.
 */
public final class ReassemblingHandshakeMessage extends HandshakeMessage {

	// Members ////////////////////////////////////////////////////////

	/** The reassembled fragments handshake body. */
	private final byte[] reassembledBytes;

	/** The handshake message's type. */
	private final HandshakeType type;

	/** The list of fragment ranges. */
	private final List<FragmentRange> fragments = new ArrayList<>(8);

	private static class FragmentRange {

		private int offset;
		private int length;
		private int end;

		private FragmentRange(int offset, int length) {
			this.offset = offset;
			this.length = length;
			this.end = offset + length;
		}

	}

	/**
	 * End of completed data, fragments without gap.
	 */
	private int completedEnd;

	// Constructors ///////////////////////////////////////////////////

	/**
	 * Called when reassembling a handshake message or received a fragment
	 * during the handshake.
	 * 
	 * @param message starting fragmented message
	 */
	public ReassemblingHandshakeMessage(FragmentedHandshakeMessage message) {
		super(message.getPeer());
		setMessageSeq(message.getMessageSeq());
		this.type = message.getMessageType();
		this.reassembledBytes = new byte[message.getMessageLength()];
		add(message);
	}

	// Methods ////////////////////////////////////////////////////////

	/**
	 * Add data of fragment to reassembled data.
	 * 
	 * @param message fragmented handshake message
	 * @return {@code true} if reassembling is completed
	 * @throws IllegalArgumentException if type, sequence number or total
	 *             message length doesn't match the previous fragments. Or the
	 *             fragment exceeds the handshake message.
	 */
	public boolean add(FragmentedHandshakeMessage message) {
		if (type != message.getMessageType()) {
			throw new IllegalArgumentException(
					"Fragment message type " + message.getMessageType() + " differs from " + type + "!");
		} else if (getMessageSeq() != message.getMessageSeq()) {
			throw new IllegalArgumentException("Fragment message sequence number " + message.getMessageSeq()
					+ " differs from " + getMessageSeq() + "!");
		} else if (getMessageLength() != message.getMessageLength()) {
			throw new IllegalArgumentException("Fragment message length " + message.getMessageLength()
					+ " differs from " + getMessageLength() + "!");
		}
		if (getMessageLength() <= completedEnd) {
			return true;
		}
		FragmentRange newRange = new FragmentRange(message.getFragmentOffset(), message.getFragmentLength());
		if (getMessageLength() < newRange.end) {
			throw new IllegalArgumentException(
					"Fragment message " + newRange.end + " bytes exceeds message " + getMessageLength() + " bytes!");
		}
		if (newRange.end <= completedEnd) {
			// already assembled
			return false;
		}
		boolean add = true;
		for (int position = 0; position < fragments.size(); ++position) {
			FragmentRange currentRange = fragments.get(position);
			if (newRange.offset <= currentRange.offset) {
				fragments.add(position, newRange);
				add = false;
				break;
			} else if (newRange.end <= currentRange.end) {
				// overlap, already assembled
				return false;
			}
		}
		if (add) {
			fragments.add(newRange);
		}
		System.arraycopy(message.fragmentToByteArray(), 0, reassembledBytes, newRange.offset, newRange.length);
		int end = completedEnd;
		for (int position = 0; position < fragments.size(); ++position) {
			FragmentRange currentRange = fragments.get(position);
			// search for end of reassembled data
			if (currentRange.offset <= end) {
				// continue data at the end
				if (end < currentRange.end) {
					end = currentRange.end;
				}
			} else {
				// gap
				if (1 < position) {
					while (1 < position) {
						// cleanup
						fragments.remove(0);
						--position;
					}
					currentRange = fragments.get(0);
					currentRange.offset = 0;
					currentRange.length = end;
					currentRange.end = end;
				}
				break;
			}
		}
		completedEnd = end;
		return getMessageLength() <= completedEnd;
	}

	@Override
	public HandshakeType getMessageType() {
		return type;
	}

	@Override
	public int getMessageLength() {
		return reassembledBytes.length;
	}

	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		sb.append("\tReassembled Handshake Protocol");
		sb.append(StringUtil.lineSeparator()).append("\tType: ").append(getMessageType());
		sb.append(StringUtil.lineSeparator()).append("\tPeer: ").append(getPeer());
		sb.append(StringUtil.lineSeparator()).append("\tMessage Sequence No: ").append(getMessageSeq());
		sb.append(StringUtil.lineSeparator()).append("\tFragment Offset: ").append(getFragmentOffset());
		sb.append(StringUtil.lineSeparator()).append("\tFragment Length: ").append(getFragmentLength());
		sb.append(StringUtil.lineSeparator()).append("\tLength: ").append(getMessageLength());
		sb.append(StringUtil.lineSeparator());

		return sb.toString();
	}

	// Serialization //////////////////////////////////////////////////

	@Override
	public byte[] fragmentToByteArray() {
		return reassembledBytes;
	}

}
