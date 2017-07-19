/**
 \file 		ixp.h
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

#ifndef __IXP_H_
#define __IXP_H_

#include "../../../abycore/circuit/booleancircuits.h"
#include "../../../abycore/circuit/arithmeticcircuits.h"
#include "../../../abycore/circuit/circuit.h"
#include "../../../abycore/aby/abyparty.h"

#include <cassert>

int32_t init_ixp_circuit(e_role role, char* address, seclvl seclvl, uint32_t num_routes, e_mt_gen_alg mt_alg,
		uint32_t test_val, uint32_t mode, uint32_t outsourced, uint32_t num_as, uint16_t port);

#endif /* __IXP_H_ */
