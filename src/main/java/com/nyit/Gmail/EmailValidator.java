package com.nyit.Gmail;

public class EmailValidator {

	public static boolean isValidEmail(String isSpfValid, String isDmarcValid, String isDkimValid, Integer positives,
			Integer total) {

		int positivePer = 0;

		if (0 != total) {

			positivePer = (int) Math.round(calculatePercentage(positives, total));
		}

		if (0 == positivePer) {
			if (isSpfValid.equalsIgnoreCase(EmailConstants.TRUE) && isDmarcValid.equalsIgnoreCase(EmailConstants.TRUE)
					&& isDkimValid.equalsIgnoreCase(EmailConstants.TRUE)) {
				return true;
			} else if (isSpfValid.equalsIgnoreCase(EmailConstants.FALSE)
					&& (isDmarcValid.equalsIgnoreCase(EmailConstants.TRUE)
							&& isDkimValid.equalsIgnoreCase(EmailConstants.TRUE))) {
				return true;
			} else if (isSpfValid.equalsIgnoreCase(EmailConstants.TRUE)
					&& isDmarcValid.equalsIgnoreCase(EmailConstants.FALSE)
					&& isDkimValid.equalsIgnoreCase(EmailConstants.TRUE)) {
				return false;
			} else if (isSpfValid.equalsIgnoreCase(EmailConstants.TRUE)
					&& isDmarcValid.equalsIgnoreCase(EmailConstants.FALSE)
					&& isDkimValid.equalsIgnoreCase(EmailConstants.FALSE)) {
				return false;
			} else if (isSpfValid.equalsIgnoreCase(EmailConstants.TRUE)
					&& isDmarcValid.equalsIgnoreCase(EmailConstants.TRUE)
					&& isDkimValid.equalsIgnoreCase(EmailConstants.FALSE)) {
				return false;
			} else if (isSpfValid.equalsIgnoreCase(EmailConstants.TRUE)
					&& isDmarcValid.equalsIgnoreCase(EmailConstants.NOT_FOUND)
					&& isDkimValid.equalsIgnoreCase(EmailConstants.FALSE)) {
				return false;
			} else if (isSpfValid.equalsIgnoreCase(EmailConstants.FALSE)
					&& isDmarcValid.equalsIgnoreCase(EmailConstants.NOT_FOUND)
					&& isDkimValid.equalsIgnoreCase(EmailConstants.FALSE)) {
				return false;
			} else if (isSpfValid.equalsIgnoreCase(EmailConstants.NOT_FOUND)
					&& isDmarcValid.equalsIgnoreCase(EmailConstants.NOT_FOUND)
					&& isDkimValid.equalsIgnoreCase(EmailConstants.NOT_FOUND)) {
				return false;
			} else if (isSpfValid.equalsIgnoreCase(EmailConstants.NOT_FOUND)
					&& isDmarcValid.equalsIgnoreCase(EmailConstants.FALSE)
					&& isDkimValid.equalsIgnoreCase(EmailConstants.FALSE)) {
				return false;
			} else if (isSpfValid.equalsIgnoreCase(EmailConstants.FALSE)
					&& isDmarcValid.equalsIgnoreCase(EmailConstants.NOT_FOUND)
					&& isDkimValid.equalsIgnoreCase(EmailConstants.NOT_FOUND)) {
				return false;
			} else if (isSpfValid.equalsIgnoreCase(EmailConstants.TRUE)
					&& isDmarcValid.equalsIgnoreCase(EmailConstants.TRUE)
					&& isDkimValid.equalsIgnoreCase(EmailConstants.NOT_FOUND)) {
				return false;
			} else if (isSpfValid.equalsIgnoreCase(EmailConstants.TRUE)
					&& isDmarcValid.equalsIgnoreCase(EmailConstants.NOT_FOUND)
					&& isDkimValid.equalsIgnoreCase(EmailConstants.NOT_FOUND)) {
				return false;
			} else if (isSpfValid.equalsIgnoreCase(EmailConstants.TRUE)
					&& isDmarcValid.equalsIgnoreCase(EmailConstants.FALSE)
					&& isDkimValid.equalsIgnoreCase(EmailConstants.NOT_FOUND)) {
				return false;
			} else if (isSpfValid.equalsIgnoreCase(EmailConstants.TRUE)
					&& isDmarcValid.equalsIgnoreCase(EmailConstants.TRUE)
					&& isDkimValid.equalsIgnoreCase(EmailConstants.NOT_FOUND)) {
				return true;
			} 
		} else {

			if (isSpfValid.equalsIgnoreCase(EmailConstants.TRUE) && isDmarcValid.equalsIgnoreCase(EmailConstants.TRUE)
					&& isDkimValid.equalsIgnoreCase(EmailConstants.TRUE) && positivePer < 3) {
				return true;
			} else if (isSpfValid.equalsIgnoreCase(EmailConstants.FALSE)
					&& (isDmarcValid.equalsIgnoreCase(EmailConstants.TRUE)
							&& isDkimValid.equalsIgnoreCase(EmailConstants.TRUE) && positivePer < 3)) {
				return true;
			} else if (isSpfValid.equalsIgnoreCase(EmailConstants.TRUE)
					&& isDmarcValid.equalsIgnoreCase(EmailConstants.FALSE)
					&& isDkimValid.equalsIgnoreCase(EmailConstants.TRUE) && positivePer > 3) {
				return false;
			} else if (isSpfValid.equalsIgnoreCase(EmailConstants.TRUE)
					&& isDmarcValid.equalsIgnoreCase(EmailConstants.FALSE)
					&& isDkimValid.equalsIgnoreCase(EmailConstants.FALSE) && positivePer > 3) {
				return false;
			} else if (isSpfValid.equalsIgnoreCase(EmailConstants.TRUE)
					&& isDmarcValid.equalsIgnoreCase(EmailConstants.TRUE)
					&& isDkimValid.equalsIgnoreCase(EmailConstants.FALSE) && positivePer > 3) {
				return false;
			} else if (isSpfValid.equalsIgnoreCase(EmailConstants.TRUE)
					&& isDmarcValid.equalsIgnoreCase(EmailConstants.TRUE)
					&& isDkimValid.equalsIgnoreCase(EmailConstants.TRUE) && positivePer > 15) {
				return false;
			} else if (isSpfValid.equalsIgnoreCase(EmailConstants.TRUE)
					&& isDmarcValid.equalsIgnoreCase(EmailConstants.NOT_FOUND)
					&& isDkimValid.equalsIgnoreCase(EmailConstants.FALSE) && positivePer > 3) {
				return false;
			} else if (isSpfValid.equalsIgnoreCase(EmailConstants.FALSE)
					&& isDmarcValid.equalsIgnoreCase(EmailConstants.NOT_FOUND)
					&& isDkimValid.equalsIgnoreCase(EmailConstants.FALSE) && positivePer > 3) {
				return false;
			} else if (isSpfValid.equalsIgnoreCase(EmailConstants.NOT_FOUND)
					&& isDmarcValid.equalsIgnoreCase(EmailConstants.NOT_FOUND)
					&& isDkimValid.equalsIgnoreCase(EmailConstants.NOT_FOUND) && positivePer > 3) {
				return false;
			} else if (isSpfValid.equalsIgnoreCase(EmailConstants.NOT_FOUND)
					&& isDmarcValid.equalsIgnoreCase(EmailConstants.FALSE)
					&& isDkimValid.equalsIgnoreCase(EmailConstants.FALSE) && positivePer > 3) {
				return false;
			} else if (isSpfValid.equalsIgnoreCase(EmailConstants.FALSE)
					&& isDmarcValid.equalsIgnoreCase(EmailConstants.NOT_FOUND)
					&& isDkimValid.equalsIgnoreCase(EmailConstants.NOT_FOUND) && positivePer > 3) {
				return false;
			} else if (isSpfValid.equalsIgnoreCase(EmailConstants.TRUE)
					&& isDmarcValid.equalsIgnoreCase(EmailConstants.TRUE)
					&& isDkimValid.equalsIgnoreCase(EmailConstants.NOT_FOUND)&& positivePer < 3) {
				return true;
			} else if (isSpfValid.equalsIgnoreCase(EmailConstants.TRUE)
					&& isDmarcValid.equalsIgnoreCase(EmailConstants.TRUE)
					&& isDkimValid.equalsIgnoreCase(EmailConstants.NOT_FOUND) && positivePer > 10) {
				return false;
			} else if (isSpfValid.equalsIgnoreCase(EmailConstants.TRUE)
					&& isDmarcValid.equalsIgnoreCase(EmailConstants.NOT_FOUND)
					&& isDkimValid.equalsIgnoreCase(EmailConstants.NOT_FOUND) && positivePer > 10) {
				return false;
			} else if (isSpfValid.equalsIgnoreCase(EmailConstants.TRUE)
					&& isDmarcValid.equalsIgnoreCase(EmailConstants.FALSE)
					&& isDkimValid.equalsIgnoreCase(EmailConstants.NOT_FOUND) && positivePer > 10) {
				return false;
			} else if (isSpfValid.equalsIgnoreCase(EmailConstants.NOT_FOUND)
					|| isDmarcValid.equalsIgnoreCase(EmailConstants.NOT_FOUND)
					|| isDkimValid.equalsIgnoreCase(EmailConstants.NOT_FOUND)) {
				if (positivePer > 15) {
					return false;
				} else {
					return true;
				}
			}
		}
		return false;

	}

	public static double calculatePercentage(Integer positives, Integer total) {
		return positives * 100 / total;
	}

	public static void main(String args[]) {
		System.out.println(calculatePercentage(10, 89));
	}

}
