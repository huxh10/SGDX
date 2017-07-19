/**
 \file 		ArithCBitVector.cpp
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

#include "ArithCBitVector.h"

/* Definitions of Constructors and Destructors. */

ArithCBitVector::ArithCBitVector() {
	m_nElementLength 	= 0;
	m_nNumberElements 	= 0;
	m_vArbitraryVector 	= NULL;
}

ArithCBitVector::ArithCBitVector(CBitVector vec) {

	ArithCBitVector(vec.GetArr(),vec.GetElementLength(),vec.GetSize());

}

ArithCBitVector::~ArithCBitVector() {
/*	if(m_vArbitraryVector) {
		free(m_vArbitraryVector);
	}
	m_vArbitraryVector = NULL;*/
}

void ArithCBitVector::deAlloc() {
	if(m_vArbitraryVector) {
		free(m_vArbitraryVector);
	}
	m_vArbitraryVector = NULL;
}

/* Definitions of  Setter and getter for Arbitrary Vector */
void ArithCBitVector::setArbitraryVector(mpz_t* arbVec) {

	int iter=0;
	if(m_vArbitraryVector) {
		free(m_vArbitraryVector);
	}
	m_vArbitraryVector = (mpz_t*) malloc(m_nNumberElements*sizeof(m_nElementLength));
	for(;iter<m_nNumberElements;iter++) {
		mpz_init_set(m_vArbitraryVector[iter],arbVec[iter]);
	}
}

mpz_t* ArithCBitVector::getArbitraryVector() {

	return m_vArbitraryVector;
}

/* Definitions of Setter and getter for Element Length */
void ArithCBitVector::setElementLength(u_int64_t ele_len) {

	m_nElementLength = ele_len;
}

u_int64_t ArithCBitVector::getElementLength() {

	return m_nElementLength;
}

/* Definitions of Setter and getter for Number of Elements */
void ArithCBitVector::setNumberElements(u_int64_t nvals) {

	m_nNumberElements = nvals;
}

u_int64_t ArithCBitVector::getNumberElements() {

	return m_nNumberElements;
}
/* Definitions of Translation Methods */

void ArithCBitVector::COPY(ArithCBitVector vec) {

	setElementLength(vec.getElementLength());
	setNumberElements(vec.getNumberElements());
	setArbitraryVector(vec.getArbitraryVector());
}


CBitVector ArithCBitVector::toCBitVector() {

	CBitVector vec;
	int iter = 0;

	BYTE *arr = toByteArray();
	vec.CreateBytes(m_nNumberElements*m_nElementLength);
	vec.ResizeinBytes(m_nNumberElements*m_nElementLength);
	vec.SetBits(arr,(uint64_t)0,(m_nNumberElements*(m_nElementLength<<3)));
	return vec;
}

void ArithCBitVector::fromCBitVector(CBitVector vec) {

	fromByteArray(vec.GetArr(),vec.GetElementLength(),vec.GetSize());
}

BYTE* ArithCBitVector::toByteArray() {

	int iter = 0;
	BYTE *arr = (BYTE*)malloc(m_nElementLength*m_nNumberElements);
	for(;iter<m_nNumberElements;iter++) {
		mpz_export((arr+m_nElementLength*iter),NULL,eBigEndian,m_nElementLength,eBigEndian,0,m_vArbitraryVector[iter]);
	}
	return arr;
}

void ArithCBitVector::fromByteArray(BYTE* array,u_int64_t ele_len,u_int64_t nvals) {

	int iter = 0;
	m_nElementLength	= ele_len;
	m_nNumberElements	= nvals;
	if(m_vArbitraryVector) {
		free(m_vArbitraryVector);
	}
	m_vArbitraryVector = (mpz_t*) malloc(m_nNumberElements*sizeof(m_nElementLength));
	for(;iter<nvals;iter++) {
		mpz_init(m_vArbitraryVector[iter]);
		mpz_import(m_vArbitraryVector[iter],1,eBigEndian,m_nElementLength,0,0,(array+ele_len*iter));
	}
}

/* Definitions of Operational Methods */

void ArithCBitVector::ADDVector(ArithCBitVector vec) {

	int iter = 0;
	mpz_t *temp_vector = (mpz_t*) malloc(m_nNumberElements*sizeof(m_nElementLength));
	for(;iter<m_nNumberElements;iter++) {
		mpz_init_set(temp_vector[iter],m_vArbitraryVector[iter]);
		mpz_add(m_vArbitraryVector[iter],temp_vector[iter],(vec.getArbitraryVector())[iter]);
	}
	free(temp_vector);
}

void ArithCBitVector::SUBVector(ArithCBitVector vec) {

	int iter = 0;
	mpz_t *temp_vector = (mpz_t*) malloc(m_nNumberElements*sizeof(m_nElementLength));
	mpz_t *max_vector  = (mpz_t*) malloc(m_nNumberElements*sizeof(m_nElementLength));


	/*
	 	If the op1 vector is lesser than op2 vector in subtraction then 2's complement method needs to
	 	be adopted.
	 	maxNum = pow(2,maxSize)-1
	 	res = maxNum - op2 + op1 + 1
	 */
	if(arithCMP(vec,eBigEndian)==eCMPResLesser) {

		for(;iter<m_nNumberElements;iter++) {
			mpz_init_set(temp_vector[iter],m_vArbitraryVector[iter]);
			mpz_init(max_vector[iter]);
			mpz_ui_pow_ui(max_vector[iter],2,m_nElementLength*8);
			mpz_sub_ui(max_vector[iter],max_vector[iter],1);
			mpz_sub(m_vArbitraryVector[iter],max_vector[iter],(vec.getArbitraryVector())[iter]);
			mpz_add(m_vArbitraryVector[iter],m_vArbitraryVector[iter],temp_vector[iter]);
			mpz_add_ui(m_vArbitraryVector[iter],m_vArbitraryVector[iter],1);
		}
	}
	else {
		for(;iter<m_nNumberElements;iter++) {
			mpz_init_set(temp_vector[iter],m_vArbitraryVector[iter]);
			mpz_sub(m_vArbitraryVector[iter],temp_vector[iter],(vec.getArbitraryVector())[iter]);
		}
	}
	free(temp_vector);
	free(max_vector);
}

void ArithCBitVector::MULVector(ArithCBitVector vec) {


	int iter = 0;
	mpz_t *temp_vector = (mpz_t*) malloc(m_nNumberElements*sizeof(m_nElementLength));
	for(;iter<m_nNumberElements;iter++) {
		mpz_init_set(temp_vector[iter],m_vArbitraryVector[iter]);
		mpz_mul(m_vArbitraryVector[iter],temp_vector[iter],(vec.getArbitraryVector())[iter]);
	}
	free(temp_vector);
}

void ArithCBitVector::MODVector(ArithCBitVector vec) {


	int iter = 0;
	mpz_t *temp_vector = (mpz_t*) malloc(m_nNumberElements*sizeof(m_nElementLength));
	for(;iter<m_nNumberElements;iter++) {
		mpz_init_set(temp_vector[iter],m_vArbitraryVector[iter]);
		mpz_mod(m_vArbitraryVector[iter],temp_vector[iter],(vec.getArbitraryVector())[iter]);
	}
	free(temp_vector);
}



void ArithCBitVector::SETAndADDVectors(ArithCBitVector A,ArithCBitVector B) {

	COPY(A);
	ADDVector(B);
}

void ArithCBitVector::SETAndSUBVectors(ArithCBitVector A,ArithCBitVector B) {

	COPY(A);
	SUBVector(B);
}

void ArithCBitVector::SETAndMULVectors(ArithCBitVector A,ArithCBitVector B) {

	COPY(A);
	MULVector(B);
}

void ArithCBitVector::SETAndMODVectors(ArithCBitVector A,ArithCBitVector B) {

	COPY(A);
	MODVector(B);
}

void ArithCBitVector::PrintContents() {

	int iter=0;
	for(;iter<m_nNumberElements;iter++) {
		gmp_printf ("%Zd ",m_vArbitraryVector[iter]);
	}
	printf("\n");

}

BOOL ArithCBitVector::isArithEqual(ArithCBitVector vec) {

	if((vec.getElementLength() == getElementLength())&&(vec.getNumberElements() == getNumberElements())) {

		int iter = 0;
		for(;iter<getNumberElements();iter++) {

			if(mpz_cmp(vec.getArbitraryVector()[iter],m_vArbitraryVector[iter])!=0) {
				return false;
			}
		}
		return true;
	}	else {

		return false;
	}
}

eCMPRes ArithCBitVector::arithCMP(ArithCBitVector vec,eEndian endianess) {


	if((vec.getElementLength()*vec.getNumberElements()) == (getElementLength()*getNumberElements())) {

		if(isArithEqual(vec)) {
			return eCMPResEqual;
		} else {

			int iter = (endianess==eBigEndian)? 0:getNumberElements()-1;
			int iter_lim= (endianess==eBigEndian)? getNumberElements():0;
			int cmpres;
			if(endianess==eBigEndian) {
				for(;iter<iter_lim;iter++) {

					cmpres = mpz_cmp(m_vArbitraryVector[iter],vec.getArbitraryVector()[iter]);
					if(cmpres==0) {
						continue;
					}
					else if(cmpres<0) {
						return eCMPResLesser;
					}
					else {
						return eCMPResGreater;
					}
				}
			}
			else {
				for(;iter>=iter_lim;iter--) {

					cmpres = mpz_cmp(m_vArbitraryVector[iter],vec.getArbitraryVector()[iter]);
					if(cmpres<0) {
						return eCMPResLesser;
					}
					else if(cmpres>0) {
						return eCMPResGreater;
					}
				}
			}
		}
	}
	else if((getElementLength()*getNumberElements()) > (vec.getElementLength()*vec.getNumberElements())) {

		return eCMPResInvalid;
	}
	else if((getElementLength()*getNumberElements()) < (vec.getElementLength()*vec.getNumberElements())) {

		return eCMPResInvalid;
	}
}
