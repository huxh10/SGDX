/**
 \file 		ixp_test.cpp
 \author	daniel.demmler@crisp-da.de
 \copyright	ABY - A Framework for Efficient Mixed-protocol Secure Two-party Computation
 Copyright (C) 2016 Engineering Cryptographic Protocols Group, TU Darmstadt
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
 \brief		IXP Test implementation.
 */

//Utility libs
#include "../../abycore/util/crypto/crypto.h"
#include "../../abycore/util/parse_options.h"
//ABY Party class
#include "../../abycore/aby/abyparty.h"

#include "common/ixp.h"

int32_t read_test_options(int32_t* argcp, char*** argvp, e_role* role, uint32_t* bitlen, uint32_t* secparam,
		string* address, uint16_t* port, uint32_t* test_val, uint32_t* mode, uint32_t* outsourced, uint32_t* num_as) {

	uint32_t int_role = 0, int_port = 0;
	bool useffc = false;

	parsing_ctx options[] = {
			{ (void*) &int_role, T_NUM, 'r', "Role: 0/1", true, false },
			{ (void*) bitlen, T_NUM, 'b', "Number of Routes, default 32", false, false },
			{ (void*) secparam, T_NUM, 's',	"Symmetric Security Bits, default: 128", false, false },
			{ (void*) address, T_STR, 'a', "IP-address of server, default: localhost", false, false },
			{ (void*) &int_port, T_NUM, 'p', "Port, default: 7766",	false, false },
			{ (void*) test_val, T_NUM, 'n', "Test value for debugging", false, false },
			{ (void*) num_as, T_NUM, 'm', "Number of ASes. default: 594", false, false },
			{ (void*) outsourced, T_NUM, 'o', "Outsourced 0(no), 1(yes), 2(debug). default: 0", false, false },
			{ (void*) mode, T_NUM, 'f', "Function: 0=Single, 1=All, 2=Prio, 3=Interactive. default: 0", false, false }
	};

	if (!parse_options(argcp, argvp, options, sizeof(options) / sizeof(parsing_ctx))) {
		print_usage(*argvp[0], options, sizeof(options) / sizeof(parsing_ctx));
		cout << "Exiting" << endl;
		exit(0);
	}

	assert(int_role < 2);
	*role = (e_role) int_role;

	if (int_port != 0) {
		assert(int_port < 1 << (sizeof(uint16_t) * 8));
		*port = (uint16_t) int_port;
	}

	cout << endl;

	return 1;
}


int main(int argc, char** argv) {
	e_role role;
	uint32_t bitlen = 32, secparam = 128, test_val = 0;
	uint16_t port = 7766;
	string address = "127.0.0.1";
	uint32_t mode = 0;
	uint32_t outsourced = 0;
	uint32_t num_as = 750;
	e_mt_gen_alg mt_alg = MT_OT;

	timespec tstart, tend;
	clock_gettime(CLOCK_MONOTONIC, &tstart);

	read_test_options(&argc, &argv, &role, &bitlen, &secparam, &address, &port, &test_val, &mode, &outsourced, &num_as);

	seclvl seclvl = get_sec_lvl(secparam);


	if(mode < 4){
		init_ixp_circuit(role, (char*) address.c_str(), seclvl, bitlen, mt_alg, test_val, mode, outsourced, num_as, port);
	}
	else{
		cerr << "unknown mode " << mode << " specified!" << endl;
	}

	clock_gettime(CLOCK_MONOTONIC, &tend);

	//cout << "overall time " << getMillies(tstart, tend) << endl;

	//cout << "IXP circuit finished." << endl;

	return 0;
}
