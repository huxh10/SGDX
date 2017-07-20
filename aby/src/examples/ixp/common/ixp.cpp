/**
 \file 		ixp.cpp
 \author 	daniel.demmler@crisp-da.de
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
 */

#include "ixp.h"

#define IXP_DBG_OUT_COARSE 0
#define IXP_DBG_OUT 0
#define IXP_MUX_DBG 0
#define IXP_PREF_DBG 0
#define IXP_PRINT_RESULT 1
#define IXP_LINEBREAK 1


void parseBytes(string s, uint8_t * res) {
	char * cp = (char*) s.c_str();

	assert(s.length() % 2 == 0);

	for (uint32_t i = 0; i < s.length() / 2; i++) {
		sscanf(cp, "%2hhx", res);
		cp += 2;
		res += 1;
	}
}

void parseUInts(string s, uint32_t * res) {
	char * cp = (char*) s.c_str();

	assert(s.length() % 8 == 0);

	for (uint32_t i = 0; i < s.length() / 8; i++) {
		sscanf(cp, "%08x", res);
		cp += 8;
		res += 1;
	}
}


/**
 * finds the first (highest priority) route that can be published to an AS
 * passes the result through a MUX tree
 * @param circ - the circuit object
 * @param shr_k -  the keys (with appended indices)
 * @param shr_v - the publish matrix
 * @param num_routes - the number of routes (keys)
 */
void PutOrMuxTree(BooleanCircuit *circ, share*** shr_k, share*** shr_cond, uint32_t num_routes) {

	while (num_routes > 1) {
		uint32_t j = 0;
		uint32_t i = 0;
		while(i < num_routes){
			if (i + 1 >= num_routes) {
				(*shr_k)[j] = (*shr_k)[i];
				i++;
			} else {
				(*shr_k)[j] = circ->PutVecANDMUXGate((*shr_k)[i], (*shr_k)[i + 1], (*shr_cond)[i]); // cond ? a : b !
				(*shr_cond)[j] = circ->PutORGate((*shr_cond)[i], (*shr_cond)[i + 1]);
				i += 2;
			}
			j++;
		}
		num_routes = j;
	}
}

void PutGEMuxTree(BooleanCircuit *circ, share*** shr_k, share*** shr_cond, uint32_t num_routes) {

	while (num_routes > 1) {
		uint32_t j = 0;
		uint32_t i = 0;
		while(i < num_routes){
			if (i + 1 >= num_routes) {
				(*shr_k)[j] = (*shr_k)[i];
				i++;
			} else {
				(*shr_k)[j] = circ->PutVecANDMUXGate((*shr_k)[i], (*shr_k)[i + 1], (*shr_cond)[i]); // cond ? a : b !
				(*shr_cond)[j] = circ->PutGEGate((*shr_cond)[i], (*shr_cond)[i + 1]);
				i += 2;
			}
			j++;
		}
		num_routes = j;
	}
}


/**
 * filters data based on a set of filter bits.
 * if filter bit == 1, the data is passed through.
 * if filter bit == 0, a default value (from the last data entry) is returned on that position
 * e.g. returns all route keys that can be published to an AS, zero otherwise.
 * @param circ - the circuit object
 * @param shr_data -  the data to filter (e.g. keys with appended indices) and the default (e.g. zero) value
 * @param shr_cond - the publish matrix (export policy)
 * @param len - the number of entries to filter (==routes (keys))
 */
void Filter(BooleanCircuit *circ, share*** shr_data, share*** shr_cond, uint32_t len, uint32_t mode) {
    if (mode == 3) {
	    for(uint32_t i = 1; i < len; ++i) {
		    (*shr_data)[i] = circ->PutVecANDMUXGate((*shr_data)[i], (*shr_data)[0], (*shr_cond)[1]); // cond ? a : b
	    }
        return;
    }
	// a number of MUXes that pass through the data if cond==1 or dummy data (from shr_data[len-1])
	for(uint32_t i = 1; i < len; ++i) {
		(*shr_data)[i] = circ->PutVecANDMUXGate((*shr_data)[i], (*shr_data)[0], (*shr_cond)[i]); // cond ? a : b
	}
}


/**
 * filters data based on a set of filter bits.
 * if filter bit == 1, the data is passed through.
 * if filter bit == 0, a default value (from the first data entry) is returned on that position
 * e.g. returns all preferences that belong to routes that can be published to an AS, zero otherwise.
 * @param circ - the circuit object
 * @param shr_data -  the data to filter (e.g. preferences) and the default (e.g. zero) value
 * @param shr_cond - the publish matrix (export policy)
 * @param len - the number of entries to filter (==routes (keys))
 */
void Filter_Pref(BooleanCircuit *circ, share*** shr_data, share*** shr_cond, uint32_t len, uint32_t mode) {
    if (mode == 4) {
        for (uint32_t i = 1; i < len; ++i) {
		    (*shr_data)[i] = circ->PutVecANDMUXGate((*shr_data)[i], (*shr_data)[0], (*shr_cond)[1]); // cond ? a : b
        }
        return;
    }
	// a number of MUXes that pass through the data if cond==1 or dummy data (from shr_data[0])
	for(uint32_t i = 1; i < len; ++i) {
		(*shr_data)[i] = circ->PutVecANDMUXGate((*shr_data)[i], (*shr_data)[0], (*shr_cond)[i]); // cond ? a : b
	}
}


int32_t test_ixp_circuit(e_role role, ABYParty* party, uint32_t num_routes,
		uint32_t test_val, uint32_t mode, uint32_t outsourced, uint32_t num_as) {

	vector<Sharing*>& sharings = party->GetSharings();
	string input_line;

	uint32_t ixp_iterations = 1;

	// do multiple iterations for interactive outsourcing (==1) or run a predefined number of iterations. stop in any case if num_as <= 0.
	while ((outsourced == 1 || ixp_iterations-- > 0) && num_as > 0) {

		if (outsourced == 1) {
#if IXP_DBG_OUT
			cout << "input num_as and num_routes" << endl;
#endif
			// provide parameters from stdin. overwrites cmd-line parameters
			getline(cin, input_line);
			sscanf(input_line.c_str(), "%ul", &num_as);
			if (num_as > 0) {
				getline(cin, input_line);
				sscanf(input_line.c_str(), "%ul", &num_routes);
			} else{
				break;
			}
		}

		//parameters
		uint32_t id_bits = 16; // length of a route id in bits
		uint32_t key_bits = 128; // length of 1 symmetric key in bits
		uint32_t r_bytes = ceil_divide((key_bits + id_bits), 8); // bytes of 1 route (key+id), padded to byte
		uint32_t rt_bytes = ceil_divide(num_routes, 8); // bytes of the transposed routes, padded to byte
		uint32_t total_r_bytes = r_bytes * num_routes; // total number of bytes of all routes
		uint32_t num_kt = (key_bits + id_bits) * rt_bytes; // length of the transposed keys (once).


		assert(id_bits % 8 == 0);
		assert(key_bits % 8 == 0);

#if IXP_DBG_OUT_COARSE
		cout << "id_size: " << id_bits << " num_routes: " << num_routes << " num_as: " << num_as << " key_bits: " << key_bits << " testval: " << test_val << endl;
#endif

		uint32_t *in_v = (uint32_t *) calloc(sizeof(uint32_t), num_as); // the "publish" matrix
		uint8_t *in_k = (uint8_t *) calloc(sizeof(uint8_t), total_r_bytes); // keys+ids
		uint8_t *kt = (uint8_t *) calloc(sizeof(uint8_t), num_kt * num_as); // transposed keys+ids

		if (outsourced % 2 == 0) { // not really outsourced -  use testing values for now
			// -- Set input data

			// dummy data for publish data. increasing numbers. These are strictly <= 32 bit, thus just 1 uint32_t.
			for (uint32_t i = 0; i < num_as; ++i) {
				in_v[i] = test_val; //currently set to test_val
			}

			// set keys and ids
			for (uint32_t i = 0; i < num_routes - 1; ++i) {

				// pick #routes-1 random keys
				for (uint32_t j = 0; j < r_bytes - 1; ++j) {
					in_k[i * r_bytes + j] = rand(); //i*16 + j;
#if IXP_DBG_OUT
					printf("%02x", (uint32_t) in_k[i * r_bytes + j]);
#endif
				}

				// append increasing ID
				in_k[i * r_bytes + r_bytes - 1] = i + 1; //id

#if IXP_DBG_OUT
				printf("%02x", (uint32_t) in_k[i * r_bytes + r_bytes - 1]);
				cout << endl;
#endif
			}

			// dummy key: all zeros
			for (uint32_t j = 0; j < r_bytes - 1; ++j) {
				in_k[(num_routes - 1) * r_bytes + j] = 0; //i*16 + j;
#if IXP_DBG_OUT
				printf("%02x", (uint32_t) in_k[(num_routes - 1) * r_bytes + j]);
#endif
			}

			// dummy key ID 255
			in_k[num_routes * r_bytes - 1] = 0xff; //id
#if IXP_DBG_OUT
			printf("%02x", (uint32_t) in_k[num_routes * r_bytes - 1]);
			cout << endl;
#endif

		} else { // interactively outsourced. inputs supplied via stdin
			getline(cin, input_line);
			assert(input_line.length() == num_as * 8);
			parseUInts(input_line, in_v);

			getline(cin, input_line);
			assert(input_line.length() == total_r_bytes * 2);
			parseBytes(input_line, in_k);
		}

		// transpose keys for SIMD processing
		for (uint32_t r = 0; r < num_routes; ++r) {
			for (uint32_t b = 0; b < key_bits + id_bits; ++b) {
				uint8_t read = (in_k[b / 8 + r * r_bytes] >> (7 - (b % 8)) & 1);
				kt[b * rt_bytes + r / 8] |= read << (r % 8);
			}
		}

		// copy transposed keys for every AS to use SIMD processing
		for (uint32_t i = 1; i < num_as; ++i) {
			memcpy(kt + i * num_kt, kt, num_kt);
		}

#if IXP_DBG_OUT
		cout << "Starting to build the IXP circuit..." << endl;
#endif

		BooleanCircuit* circ = (BooleanCircuit*) sharings[S_BOOL]->GetCircuitBuildRoutine(); //Fixed to GMW currently

		share *shr_v, *shr_k;
        uint32_t vs_num_routes = (mode == 3) ? 2 : num_routes;
	    share** shr_keys = (share**) malloc(sizeof(share*) * num_routes);
	    share** shr_vs = (share**) malloc(sizeof(share*) * vs_num_routes);

		if (outsourced > 0) {

			// create random dummy values
			if (outsourced == 2) {

				// separate pre-shared inputs from client and server.
				// currently generated here from above dummy data.
				uint32_t *in_v_rnd = (uint32_t*) malloc(sizeof(uint32_t) * num_as);
				uint8_t *kt_rnd = (uint8_t *) malloc(sizeof(uint8_t) * num_kt * num_as);

				// generate random stream and XOR to plain text inputs
				for (uint32_t i = 0; i < num_as; ++i) {
					in_v_rnd[i] = rand();
					in_v[i] ^= in_v_rnd[i];
				}

				for (uint32_t i = 0; i < num_kt * num_as; ++i) {
					kt_rnd[i] = rand();
					kt[i] ^= kt_rnd[i];
				}
				
				// use different inputs for client and server ("pre-shared")
				if (role == SERVER) {
					shr_v = circ->PutSharedSIMDINGate(num_as, in_v_rnd, num_routes);
					shr_k = circ->PutSharedSIMDINGate((key_bits + id_bits) * num_as, kt_rnd, num_routes);
				} else {
					shr_v = circ->PutSharedSIMDINGate(num_as, in_v, num_routes);
					shr_k = circ->PutSharedSIMDINGate((key_bits + id_bits) * num_as, kt, num_routes);
				}

				// values have been copied. free memory
				free(kt_rnd);
				free(in_v_rnd);
			}
			else { // outsourced == 1
				// put SharedInput gates (no role) use stdin inputs
				shr_v = circ->PutSharedSIMDINGate(num_as, in_v, vs_num_routes);
				shr_k = circ->PutSharedSIMDINGate((key_bits + id_bits) * num_as, kt, num_routes);
			}

		} else { // no outsourcing. outsourced == 0

			// dummy inputs selected by server for benchmarking, not pre-shared (not outsourced)
			shr_v = circ->PutSIMDINGate(num_as, in_v, num_routes, SERVER);
			shr_k = circ->PutSIMDINGate((key_bits + id_bits) * num_as, kt, num_routes, SERVER);
		}

	    for (uint32_t i = 0; i < num_routes; i++) {
	    	shr_keys[i] = shr_k->get_wire_as_share(i);
	    }
        for (uint32_t i = 0; i < vs_num_routes; i++) {
	    	shr_vs[i] = shr_v->get_wire_as_share(i);
        }


#if IXP_MUX_DBG
		//	///////////////////
		// Debug output for mux cond gates
		share** shr_vs_out_pre = (share**) malloc(sizeof(share*) * num_routes);

		for (uint32_t i = 0; i < num_routes; i++) {
			shr_vs_out_pre[i] = circ->PutOUTGate(shr_vs[i], ALL);
		}
		//	//////////////////
#endif



		//The actual circuit logic depending on the selected mode
		if (mode == 0) { // SINGLE route, ordered by RS
			PutOrMuxTree(circ, &shr_keys, &shr_vs, num_routes);

			share* shr_out;
			if (outsourced > 0) {
				// result is MUX output at pos 0
				shr_out = circ->PutSharedOUTGate(shr_keys[0]);
			} else {
				// result is MUX output at pos 0
				shr_out = circ->PutOUTGate(shr_keys[0], ALL);
			}

#if IXP_MUX_DBG
			//	///////////////////
			// Debug output for mux cond gates
			share** shr_vs_out = (share**) malloc(sizeof(share*) * num_routes);

			for (uint32_t i = 0; i < num_routes; i++) {
				shr_vs_out[i] = circ->PutOUTGate(shr_vs[i], ALL);
			}
			//	//////////////////
#endif

#if IXP_DBG_OUT
			cout << "Single Route Tree Circuit built." << endl;
#endif
			// run MPC
			party->ExecCircuit();

			uint32_t *out_k, *out_k2;
			uint32_t bl, nv;

			shr_out->get_clear_value_vec(&out_k, &bl, &nv);

#if IXP_DBG_OUT
			cout << "bitlen: " << bl << " nv: " << nv << endl;
			cout << "Out_k from circuit evaluation: " << endl;
			cout << ((nv == num_as * (key_bits + id_bits)) ? "Output length correct." : "Output length wrong!") << endl;
#endif

			uint8_t *out_kb = (uint8_t *) calloc(sizeof(uint8_t), total_r_bytes * num_as); // keys+ids

			for (uint32_t i = 0; i < nv; i++) {
				out_kb[i / 8] |= (out_k[i] & 1) << 7 - (i % 8);
			}

#if IXP_PRINT_RESULT
			for (uint32_t i = 0; i < nv / 8; i++) {
#if IXP_LINEBREAK
				if (i % r_bytes == 0) {
					cout << endl;
				}
#endif
				printf("%02x", (uint32_t) out_kb[i]);
			}
			cout << endl;
#endif

#if IXP_MUX_DBG
			uint32_t *out_k2;
			//	////////////
			// Debug output of MUX cond bits
			cout << endl << "MUX bits:" << endl;

			for (uint32_t i = 0; i < num_routes; i++) {
				shr_vs_out[i]->get_clear_value_vec(&out_k, &bl, &nv);
				cout << i << ": " << nv << " " << bl << " | ";
				shr_vs_out_pre[i]->get_clear_value_vec(&out_k2, &bl, &nv);
				for(uint32_t j = 0; j < nv; j++) {
					printf("%x %x ", (uint32_t) out_k[j], (uint32_t) out_k2[j]);
				}
				cout << endl;
			}
			//	//////
#endif

			free(out_kb);
			free(shr_out);

		} else if (mode == 1 || mode == 3) { //mode == 1, simple ALL case. filters routes
			Filter(circ, &shr_keys, &shr_vs, num_routes, mode);

			share ** shr_out = (share **) calloc(sizeof(share*), num_routes);

			if (outsourced > 0) {
				for (uint32_t i = 1; i < num_routes; i++) {
					shr_out[i] = circ->PutSharedOUTGate(shr_keys[i]);
				}
			} else {
				for (uint32_t i = 1; i < num_routes; i++) {
					shr_out[i] = circ->PutOUTGate(shr_keys[i], ALL);
				}
			}

#if IXP_DBG_OUT
			cout << "ALL - Filter Circuit built." << endl;
#endif

			// run MPC
			party->ExecCircuit();

			uint32_t bl, nv;
			uint32_t *out_k;

			uint8_t *out_kb = (uint8_t *) calloc(sizeof(uint8_t), total_r_bytes * num_as);

			for (uint32_t i = 1; i < num_routes; i++) { // iterate through all result keys
				shr_out[i]->get_clear_value_vec(&out_k, &bl, &nv);

#if IXP_DBG_OUT
				cout << "bitlen: " << bl << " nv: " << nv << endl;
				cout << "Out_k from circuit evaluation: " << endl;
				cout << ((nv == num_as * (key_bits + id_bits)) ? "Output length correct." : "Output length wrong!") << endl;
#endif

				memset(out_kb, 0, total_r_bytes * num_as);

				for (uint32_t i = 0; i < nv; i++) {
					out_kb[i / 8] |= (out_k[i] & 1) << 7 - (i % 8);
				}

#if IXP_PRINT_RESULT
				for (uint32_t i = 0; i < nv / 8; i++) {
#if IXP_LINEBREAK
					if (i % r_bytes == 0) {
						cout << endl;
					}
#endif
					printf("%02x", (uint32_t) out_kb[i]);
				}
				cout << endl;
#endif
			}
			free(out_kb);
			free(shr_out);
		} else {
			cerr << "Mode not defined." << endl;
		}

		// reset for possible next iteration
		party->Reset();

		// free memory
		free(shr_keys);
		free(shr_vs);
		free(in_v);
		free(in_k);
		free(kt);
	}

	return 0;
}


int32_t test_ixp_circuit_pref(e_role role, ABYParty* party, uint32_t num_routes, uint32_t test_val, uint32_t mode, uint32_t outsourced,
		uint32_t num_as) {

	vector<Sharing*>& sharings = party->GetSharings();
	string input_line;
	
	uint32_t ixp_iterations = 1;

	// do multiple iterations for interactive outsourcing (==1) or run a predefined number of iterations. stop in any case if num_as <= 0.
	while ((outsourced == 1 || ixp_iterations-- > 0) && num_as > 0) {

		if (outsourced == 1) {
#if IXP_DBG_OUT
			cout << "input num_as and num_routes" << endl;
#endif
			// provide parameters from stdin. overwrites cmd-line parameters
			getline(cin, input_line);
			sscanf(input_line.c_str(), "%ul", &num_as);
			if (num_as > 0) {
				getline(cin, input_line);
				sscanf(input_line.c_str(), "%ul", &num_routes);
			} else {
				break;
			}
		}

		//parameters
		uint32_t id_bits = 16; // length of a route id in bits
		uint32_t key_bits = 128; // length of 1 symmetric key in bits
		uint32_t r_bytes = ceil_divide((key_bits + id_bits), 8); // bytes of 1 route (key+id), padded to byte
		uint32_t rt_bytes = ceil_divide(num_routes, 8); // bytes of the transposed routes, padded to byte
		uint32_t total_r_bytes = r_bytes * num_routes; // total number of bytes of all routes
		uint32_t p_bits = 16; // bit length of a preference
		uint32_t p_bytes = ceil_divide(p_bits, 8); // bytes of a pref, padded to full byte
		uint32_t pt_bytes = ceil_divide(num_routes, 8); // byte length of transposed prefs, padded to byte
		uint32_t num_pt = p_bits * pt_bytes;

		assert(id_bits % 8 == 0);
		assert(key_bits % 8 == 0);
		assert(p_bits % 8 == 0); // TODO investigate bit sizes <  8 bit

#if IXP_DBG_OUT_COARSE
		cout << "id_size: " << id_bits << " num_routes: " << num_routes << " num_as: " << num_as << " key_bits: " << key_bits << " p_bits: "
				<< p_bits << " testval: " << test_val << endl;
#endif

		uint32_t *in_v = (uint32_t *) calloc(sizeof(uint32_t), num_as); // the "publish" matrix
		uint8_t *in_k = (uint8_t *) calloc(sizeof(uint8_t), total_r_bytes); // keys+ids
		uint8_t *in_p = (uint8_t *) calloc(sizeof(uint8_t), num_as * num_routes * p_bytes); // the preferences. one for each route and AS.
		uint8_t *pt = (uint8_t *) calloc(sizeof(uint8_t), num_as * p_bits * pt_bytes); // the preferences. one for each route and AS


		if (outsourced % 2 == 0) {
		// -- Set input data

		// dummy data for publish data. increasing numbers. These are strictly <= 32 bit, thus just 1 uint32_t.
		for (uint32_t i = 0; i < num_as; ++i) {
			in_v[i] = test_val ; //currently set to test_val
		}

		// set keys and ids

		// dummy key: all zeros with id 0xff
		in_k[r_bytes - 1] = 0xff; //id
#if IXP_DBG_OUT
		for (uint32_t j = 0; j < r_bytes; ++j) {
			printf("%02x", (uint32_t) in_k[j]);
		}
		cout << endl;
#endif

		// valid keys with id starting from 1
		for (uint32_t i = 1; i < num_routes; ++i) {

			// pick #routes-1 random keys
			for (uint32_t j = 0; j < r_bytes - 1; ++j) {
				in_k[i * r_bytes + j] = rand(); //i*16 + j;
#if IXP_DBG_OUT
				printf("%02x", (uint32_t) in_k[i * r_bytes + j]);
#endif
			}

			// append increasing ID
			in_k[i * r_bytes + r_bytes - 1] = i; //id

#if IXP_DBG_OUT
			printf("%02x", (uint32_t) in_k[i * r_bytes + r_bytes - 1]);
			cout << endl;
#endif
		}

		// set preferences
		for (uint32_t i = 0; i < num_as; ++i) {
			for (uint32_t j = 1; j < num_routes; ++j) { // j == 0 remains zero
				in_p[i * num_routes + j] = rand(); // choose random prefs for testing
			}
		}


#if IXP_DBG_OUT
		cout << "Preferences:";
		// print input prefs
		for (uint32_t i = 0; i < num_as * num_routes; ++i) {
			if (i % num_routes == 0) {
				cout << endl;
			}
			printf("%d ", in_p[i]);
		}
		cout << endl;
#endif

		} else { // interactively outsourced. inputs supplied via stdin
			getline(cin, input_line);
			assert(input_line.length() == num_as * 8);
			parseUInts(input_line, in_v);

			getline(cin, input_line);
			assert(input_line.length() == total_r_bytes * 2);
			parseBytes(input_line, in_k);

			getline(cin, input_line);
			assert(input_line.length() == p_bytes * num_routes * num_as * 2);
			parseBytes(input_line, in_p);


		}

		// transpose preferences for SIMD processing
		for (uint32_t a = 0; a < num_as; ++a) {
			for (uint32_t r = 0; r < num_routes; ++r) {
				for (uint32_t b = 0; b < p_bits; ++b) {
					uint8_t read = (in_p[b / 8 + r * p_bytes + a * num_routes * p_bytes] >> (7 - (b % 8)) & 1);
					pt[b * pt_bytes + r / 8 + a * num_pt] |= read << (r % 8);
				}
			}
		}


#if IXP_DBG_OUT
		cout << "Starting to build the IXP circuit..." << endl;
#endif

		BooleanCircuit* circ = (BooleanCircuit*) sharings[S_BOOL]->GetCircuitBuildRoutine();

        uint32_t vs_num_routes = (mode == 4) ? 2 : num_routes;

		share *shr_v, *shr_k, *shr_p;
		share **shr_vs = (share**) malloc(sizeof(share*) * vs_num_routes);
		share **shr_prefs = (share**) malloc(sizeof(share*) * num_routes);
		share **shr_keys = (share**) malloc(sizeof(share*) * num_routes);

		if(outsourced > 0){
			if (outsourced == 2) {

				// separate pre-shared inputs from client and server.
				// currently generated here from above dummy data.
				uint32_t *in_v_rnd = (uint32_t *) malloc(sizeof(uint32_t) * num_as);
				uint8_t *in_k_rnd = (uint8_t *) malloc(sizeof(uint8_t) * total_r_bytes);
				uint8_t *pt_rnd = (uint8_t *) malloc(sizeof(uint8_t) * num_as * p_bits * pt_bytes);

				// generate random stream and XOR to plain text inputs
				for (uint32_t i = 0; i < num_as; ++i) {
					in_v_rnd[i] = rand();
					in_v[i] ^= in_v_rnd[i];
				}

				for (uint32_t i = 0; i < total_r_bytes; ++i) {
					in_k_rnd[i] = rand();
					in_k[i] ^= in_k_rnd[i];
				}
				
				for (uint32_t i = 0; i < num_as * p_bits * pt_bytes; ++i) {
					pt_rnd[i] = rand();
					pt[i] ^= pt_rnd[i];
				}

				// use different inputs for client and server ("pre-shared")
				if (role == SERVER) {
					shr_v = circ->PutSharedSIMDINGate(num_as, in_v_rnd, num_routes);
					shr_p = circ->PutSharedSIMDINGate(num_as * p_bits, pt_rnd, num_routes);
					for (uint32_t i = 0; i < num_routes; i++) {
						shr_keys[i] = circ->PutSharedINGate(in_k_rnd + i * r_bytes, key_bits + id_bits);
					}

				} else {
					shr_v = circ->PutSharedSIMDINGate(num_as, in_v, num_routes);
					shr_p = circ->PutSharedSIMDINGate(num_as * p_bits, pt, num_routes);
					for (uint32_t i = 0; i < num_routes; i++) {
						shr_keys[i] = circ->PutSharedINGate(in_k + i * r_bytes, key_bits + id_bits);
					}
				}

				// values have been copied. free memory
				free(in_k_rnd);
				free(in_v_rnd);
				free(pt_rnd);

			} else { //outsourced == 1
					 // put SharedInput gates (no role) use stdin inputs
				shr_v = circ->PutSharedSIMDINGate(num_as, in_v, vs_num_routes);
				shr_p = circ->PutSharedSIMDINGate(num_as * p_bits, pt, num_routes);
				for (uint32_t i = 0; i < num_routes; i++) {
					shr_keys[i] = circ->PutSharedINGate(in_k + i * r_bytes, key_bits + id_bits);
				}
			}

		} else { // no outsourcing. outsourced == 0

			// dummy inputs selected by server for benchmarking, not pre-shared (not outsourced)
			shr_v = circ->PutSIMDINGate(num_as, in_v, num_routes, SERVER);
			shr_p = circ->PutSIMDINGate(num_as * p_bits, pt, num_routes, SERVER);
			for (uint32_t i = 0; i < num_routes; i++) {
				shr_keys[i] = circ->PutINGate(in_k + i * r_bytes, key_bits + id_bits, SERVER);
			}

		}


		for (uint32_t i = 0; i < num_routes; i++) {
			shr_keys[i] = circ->PutRepeaterGate(num_as, shr_keys[i]);
			shr_prefs[i] = shr_p->get_wire_as_share(i);
		}
        for (uint32_t i = 0; i < vs_num_routes; i++) {
			shr_vs[i] = shr_v->get_wire_as_share(i);
        }

		//set preference of all forbidden routes to zero
		Filter_Pref(circ, &shr_prefs, &shr_vs, num_routes, mode);

		share **shr_pref_transposed = (share**) malloc(sizeof(share*) * num_routes);
		uint32_t *posids = (uint32_t*) calloc(sizeof(uint32_t), num_as);

		for (uint32_t i = 0; i < num_routes; ++i) {
			shr_pref_transposed[i] = new boolshare(p_bits, circ);

			for (uint32_t j = 0; j < p_bits; ++j) {

				// get positions to extract from prefs
				for (uint32_t k = 0; k < num_as; ++k) {
					posids[k] = num_as * p_bits - (k * p_bits + j) - 1;
				}

				// write to new share
				shr_pref_transposed[i]->set_wire(j, circ->PutSubsetGate(shr_prefs[i], posids, num_as)->get_wire(0));
			}
		}

#if IXP_PREF_DBG
		share ** shr_out_prefs = (share **) calloc(sizeof(share*), num_routes);
		share ** shr_out_prefs2 = (share **) calloc(sizeof(share*), num_routes);
		share ** shr_out_allkeys = (share**) malloc(sizeof(share*) * num_routes);

		for (uint32_t i = 0; i < num_routes; i++) {
				shr_out_prefs[i] = circ->PutOUTGate(shr_prefs[i], ALL);
				shr_out_prefs2[i] = circ->PutOUTGate(shr_pref_transposed[i], ALL);
				shr_out_allkeys[i] = circ->PutOUTGate(shr_keys[i], ALL);
			}
#endif

		share *maxpref, *maxkey;
		circ->PutMaxIdxGate(shr_pref_transposed, shr_keys, num_routes, &maxpref, &maxkey);

		share *shr_out_maxkey;
		share *shr_out_maxpref;

		if (outsourced>0){
//			shr_out_maxpref = circ->PutSharedOUTGate(maxpref);
			shr_out_maxkey = circ->PutSharedOUTGate(maxkey);
		}
		else {
//			shr_out_maxpref = circ->PutOUTGate(maxpref, ALL);
			shr_out_maxkey = circ->PutOUTGate(maxkey, ALL);
		}

		// run MPC
		party->ExecCircuit();


#if IXP_PREF_DBG
		uint32_t bl, nv;
		uint32_t *out_k, out_k_all;

		uint8_t *out_kb = (uint8_t *) calloc(sizeof(uint8_t), p_bytes * num_as * num_routes);

		for (uint32_t i = 0; i < num_routes; i++) { // iterate through all transposed prefs
			shr_out_prefs[i]->get_clear_value_vec(&out_k, &bl, &nv);

#if IXP_DBG_OUT
			cout << "bitlen: " << bl << " nv: " << nv << endl;
			cout << "prefs from circuit evaluation: " << endl;
			cout << ((nv == num_as * p_bits) ? "Output length correct." : "Output length wrong!") << endl;
#endif

			memset(out_kb, 0, p_bytes * num_as);

			for (uint32_t i = 0; i < nv; i++) {
				out_kb[i / 8] |= (out_k[i] & 1) << 7 - (i % 8);
			}

#if IXP_PRINT_RESULT
			for (uint32_t i = 0; i < nv / 8; i++) {
				printf("%02x", (uint32_t) out_kb[i]);
			}
			cout << endl;
#endif
		}


		cout << "PREFS2:" << endl << endl;

		free(out_kb);


		for (uint32_t i = 0; i < num_routes; i++) { // iterate through all transposed prefs
			shr_out_prefs2[i]->get_clear_value_vec(&out_k, &bl, &nv);

#if IXP_DBG_OUT
			cout << "bitlen: " << bl << " nv: " << nv << endl;
			cout << "pref2 from circuit evaluation: " << endl;
			cout << ((nv == num_as) ? "Output length correct." : "Output length wrong!") << endl;
#endif
			for(uint32_t j = 0; j < nv; ++j){
				printf("%x\n", *(out_k + j));
			}


		}
#endif

#if IXP_PRINT_RESULT
		CBitVector out;
		uint8_t* output;

//		cout << "All keys:\n";
//
//		for (uint32_t i = 0; i < num_routes; i++) {
//			output = shr_out_allkeys[i]->get_clear_value();
//
//			out.Reset();
//			out.AttachBuf(output, r_bytes * num_as);
//
//			cout << "Key " << i << ":\n";
//			for (uint32_t i = 0; i < num_as; ++i) {
//				out.PrintHex(i * r_bytes, (i + 1) * r_bytes);
//			}
//		}

		cout << "RESULTS:" << endl;
		output = shr_out_maxkey->get_clear_value();

		out.AttachBuf(output, r_bytes * num_as);

//		cout << "Key:\n";
#if IXP_LINEBREAK
		for (int32_t i = num_as - 1; i >= 0; --i) {
			out.PrintHex(i * r_bytes, (i + 1) * r_bytes);
		}
#else
		for (int32_t i = num_as - 1; i >= 0; --i) {
			out.PrintHex(i * r_bytes, (i + 1) * r_bytes, false);
		}
		cout << endl;
#endif //IXP_LINEBREAK

		out.Reset();

/*
		output = shr_out_maxpref->get_clear_value();

		out.AttachBuf(output, p_bytes * num_as);

//		cout << "Maxpref:\n";
#if IXP_LINEBREAK
		for (int32_t i = num_as - 1; i >= 0; --i) {
			out.PrintHex(i * p_bytes, (i + 1) * p_bytes);
		}
#else
		for (int32_t i = num_as - 1; i >= 0; --i) {
			out.PrintHex(i * p_bytes, (i + 1) * p_bytes, false);
		}
		cout << endl;
#endif //IXP_LINEBREAK
*/


#endif //IXP_PRINT_RESULT


		// reset for possible next iteration
		party->Reset();


		// free memory
		free(shr_keys);
		free(shr_vs);
		free(shr_prefs);
		free(shr_pref_transposed);
		free(in_v);
		free(in_k);
		free(in_p);
		free(pt);
		free(posids);

	}

	return 0;
}


int32_t init_ixp_circuit(e_role role, char* address, seclvl seclvl, uint32_t num_routes, e_mt_gen_alg mt_alg,
		uint32_t test_val, uint32_t mode, uint32_t outsourced, uint32_t num_as, uint16_t port) {

	ABYParty* party;

	switch (mode) {
	case 0: //single
		party = new ABYParty(role, address, seclvl, 32, 1, mt_alg, 10 * num_routes, port);
		break;
	case 1: //all
		party = new ABYParty(role, address, seclvl, 32, 1, mt_alg, 8 * num_routes, port);
		break;
	case 2: //pref
	case 3:	//interactive (uses biggest size)
#if IXP_PREF_DBG
		// printing debug info requires slightly more gates
		party = new ABYParty(role, address, seclvl, 32, 1, mt_alg, 700 * num_routes, port);
#else
		party = new ABYParty(role, address, seclvl, 32, 1, mt_alg, 500 * num_routes, port);
#endif
		break;

	}

	string input_line;

	uint32_t inner_mode = mode;

	// when interactive, read the actual mode for next iteration
	if (mode == 3) {
		getline(cin, input_line);
		sscanf(input_line.c_str(), "%ul", &inner_mode);
        cout << "inner_mode:" << inner_mode << endl;
	}

	//exit if inner_mode > 2
	while (inner_mode < 5) {
		switch (inner_mode) {
		case 0: //single
		case 1: //all
        case 3: // single export policy testing
			test_ixp_circuit(role, party, num_routes, test_val, inner_mode, outsourced, num_as);
			break;
		case 2: //pref
        case 4: // single export policy testing
			test_ixp_circuit_pref(role, party, num_routes, test_val, inner_mode, outsourced, num_as);
			break;
		}

		//read mode for next round
		if(mode==3){
			getline(cin, input_line);
			sscanf(input_line.c_str(), "%ul", &inner_mode);
            cout << "inner_mode:" << inner_mode << endl;
		}
	}

	delete party;
	return 0;
}
