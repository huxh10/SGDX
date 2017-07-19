/**
 \file 		ArithCBitVector.h
 \author 	sreeram.sadasivam@cased.de
 \copyright	ABY - A Framework for Efficient Mixed-protocol Secure Two-party Computation
			Copyright (C) 2015 Engineering Cryptographic Protocols Group, TU Darmstadt
			This program is free software: you can redistribute it and/or modify
			it under the terms of the GNU Affero General Public License as published
			by the Free Software Foundation, either version 3 of the License, or
			(at your option) any later version.
			This program is distributed in the hope that it will be useful,
			but WITHOUT ANY WARRANTY; without even the implied warranty of
			MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
			GNU Affero General Public License for more details.
			You should have received a copy of the GNU Affero General Public License
			along with this program. If not, see <http://www.gnu.org/licenses/>.
 \brief		Arithmetic CBitVector Implementation
 */

#ifndef ARITHCBITVECTOR_H_
#define ARITHCBITVECTOR_H_

#include "cbitvector.h"

/* Enumerations*/
enum eEndian {
	eLittleEndian 	=	-1, /** Little Endian format of vectorization.*/
	eBigEndian		=	 1  /** Big Endian format of vectorization.   */
};

enum eCMPRes {
	eCMPResLesser	=	-1,  /** Comparison result is less than		  */
	eCMPResEqual	=	 0,  /** Comparison result is equal			  */
	eCMPResGreater	=	 1,  /** Comparison result is greater than    */
	eCMPResInvalid	= 	-100 /** Comparison result is invalid		  */
};
/**
	ArithCBitVector class is used for performing fast arithmetic operations in convenience.
	It is derived from CBitVector. Therefore, it supports most of the CBitVector operations.

*/
class ArithCBitVector: public CBitVector {
public:
	/* Allocation and deallocation Methods. */
	ArithCBitVector();

	/**
		Constructor which sets the Arbitrary vector and its attributes with a CBitVector object.
	*/
	ArithCBitVector(CBitVector vec);

	/**
		Generic supported Constructor which sets the Arbitrary vector and its attributes.
		\param val 		value Object to be stored in the ArithCBitVector Object.
		\param ele_len 	Element Length of each element in the value object.
		\param nvals	Number of values in the Value Object.
	*/
	template<class T> ArithCBitVector(T val,uint64_t ele_len,uint64_t nvals) {

		int iter=0;
		m_nElementLength	= ele_len;
		m_nNumberElements	= nvals;
		m_vArbitraryVector = (mpz_t*) malloc(nvals*sizeof(mpz_t));
		for(;iter<nvals;iter++) {
			mpz_init(m_vArbitraryVector[iter]);
			mpz_import(m_vArbitraryVector[iter],1,eBigEndian,m_nElementLength,0,0,&val);
		}

	}
	/* Destructor */
	virtual ~ArithCBitVector();

	/**
		This method is sort of like realloc method in ArithCBitVector.
		\param val 		value Object to be stored in the ArithCBitVector Object.
		\param ele_len 	Element Length of each element in the value object.
		\param nvals	Number of values in the Value Object.
	*/
	template<class T> void AllocAndInitArbitraryVector(T val, u_int64_t ele_len,u_int64_t nvals) {

		int iter=0;
		m_nElementLength	= ele_len;
		m_nNumberElements	= nvals;
		if(m_vArbitraryVector) {
			free(m_vArbitraryVector);
			m_vArbitraryVector = NULL;
		}
		m_vArbitraryVector = (mpz_t*) malloc(nvals*sizeof(mpz_t));
		for(;iter<nvals;iter++) {
				mpz_init(m_vArbitraryVector[iter]);
				mpz_import(m_vArbitraryVector[iter],1,eBigEndian,m_nElementLength,0,0,val);
		}

	}

	/**
		Deallocates the ArithCBitVector Object. This method have to explicitly called every time whenever
		a deallocation happens.
	*/
	void deAlloc();

	/* Setter and getter for Arbitrary Vector */

	/**
		Method which sets the arbitrary vector with another arbitrary vector.
		\param	arbVec		Arbitrary vector which sets the current arbitrary vector of the class.
	*/
	void setArbitraryVector(mpz_t* arbVec);

	/**
		Method which returns the Arbitrary vector to the caller.
		\return	arbitrary vector to the caller.
	*/
	mpz_t* getArbitraryVector();

	/* Setter and getter for Element Length */

	/**
		Method which sets the arbitrary vector attribute element length with another element length.
		\param	ele_len		Element Length which is set to element length attribute of arbitrary vector.
	*/
	void setElementLength(u_int64_t ele_len);

	/**
		Method which returns the Arbitrary vector attribute element length to the caller.
		\return	arbitrary vector attribute element length to the caller.
	*/
	u_int64_t getElementLength();

	/* Setter and getter for Number of elements */

	/**
		Method which sets the arbitrary vector attribute number of values/elements with another nvals.
		\param	nvals		Number of values which is set to number of values/elements attribute of
							arbitrary vector.
	*/
	void setNumberElements(u_int64_t nvals);

	/**
		Method which returns the Arbitrary vector attribute number of values/elements to the caller.
		\return	arbitrary vector attribute number of values/elements to the caller.
	*/
	u_int64_t getNumberElements();

	/* Translation Methods. */

	/**
		Translation method which converts ArithCBitVector to CBitVector.
		\return Converted \link CBitVector \endlink Object is returned.
	*/
	CBitVector toCBitVector();

	/**
		Translation method which converts CBitVector to ArithCBitVector.
		\param vec		CBitVector from which the ArithCBitVector object is initialised.
	*/
	void fromCBitVector(CBitVector vec);

	/**
		Translation method which converts ArithCBitVector to ByteArray.
		\return Converted \link BYTE \endlink array is returned.
	*/
	BYTE* toByteArray();

	/**
		Translation method which converts from ByteArray to ArithCBitVector.
		\param array	\link BYTE \endlink array from which the ArithCBitVector is created.
		\param ele_len	Element length of elements in \link BYTE \endlink array.
		\param nvals	Number of elements in \link BYTE \endlink array.
	*/
	void fromByteArray(BYTE* array,u_int64_t ele_len,u_int64_t nvals);

	/* Management operations */
	/**
		Method which copies the ArithCBitVector to another.
		\param vec	ArithCBitVector to be copied from.
	*/
	void COPY(ArithCBitVector vec);

	/* Arithmetical Operations Methods. */

	/**
		Method which adds the ArithCBitVector to another.
		\param vec	ArithCBitVector to be added from.
	*/
	void ADDVector(ArithCBitVector vec);

	/**
		Method which subtracts from the given ArithCBitVector.
		\param vec	ArithCBitVector which subtracts from the given ArithCBitVector.
	*/
	void SUBVector(ArithCBitVector vec);

	/**
		Method which multiplies the ArithCBitVector to another.
		\param vec	ArithCBitVector to be multiplied from.
	*/
	void MULVector(ArithCBitVector vec);

	/**
		Method which performs modulus on one ArithCBitVector using another.
		\param vec	ArithCBitVector which is base of modulus.
	*/
	void MODVector(ArithCBitVector vec);

	/**
		Method which performs and copies the result of addition operation between two vectors
		into one resultant vector. Res = A + B
		\param	A	ArithCBitVector which is used as one attribute for add.
		\param	B	ArithCBitVector which is used as second attribute for add.
	*/
	void SETAndADDVectors(ArithCBitVector A,ArithCBitVector B);

	/**
		Method which performs and copies the result of subtraction operation between two vectors
		into one resultant vector. Res = A - B
		\param	A	ArithCBitVector which is used as one attribute for subtraction.
		\param	B	ArithCBitVector which is used as second attribute for subtraction.
	*/
	void SETAndSUBVectors(ArithCBitVector A,ArithCBitVector B);

	/**
		Method which performs and copies the result of multiplication operation between two vectors
		into one resultant vector. Res = A * B
		\param	A	ArithCBitVector which is used as one attribute for multiplication.
		\param	B	ArithCBitVector which is used as second attribute for multiplication.
	*/
	void SETAndMULVectors(ArithCBitVector A,ArithCBitVector B);

	/**
		Method which performs and copies the result of modulus operation between two vectors
		into one resultant vector. Res = A mod B
		\param	A	ArithCBitVector which is used as one attribute for modulus.
		\param	B	ArithCBitVector which is used as second attribute for modulus.
	*/
	void SETAndMODVectors(ArithCBitVector A,ArithCBitVector B);

	/* Display Functions */

	/**
	 	 Function which displays the content of ArithCBitVector in Byte form.
	*/
	void PrintContents();

	/** Logical Operations */

	/**
		 Function which checks the equality of two ArithCBitVectors.
		 \param 	vec		ArithCBitVector with which the equality is checked.
		 \return	Boolean result of the equality test.
	*/
	BOOL isArithEqual(ArithCBitVector vec);

	/**
		 Function which checks for comparison of two ArithCBitVectors.
		 \param 	vec		ArithCBitVector with which the equality is checked.
		 \return	Compared result which will be either -1(lesser), +1 (greater, 0(equal), -100(Invalid if lengths are unequal)
	*/
	eCMPRes arithCMP(ArithCBitVector vec,eEndian endianess);


private:
	mpz_t* 		m_vArbitraryVector; /**	Arbitrary vector which performs arithmetic operations. */
	uint64_t    m_nElementLength;   /** Element Length of the arbitrary vector. */
	uint64_t 	m_nNumberElements;  /** Number of elements in the arbitrary vector.*/


};

#endif /* ARITHCBITVECTOR_H_ */
