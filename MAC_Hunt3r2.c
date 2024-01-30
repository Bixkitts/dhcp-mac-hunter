//-------------------------------------------------------------------
//  MAC_Hunt3r2, Network analysis software
//	Copyright(C) 2023 Sean Bikkes
//
//	This program is free software : you can redistribute it and /or modify
//	it under the terms of the GNU General Public License as published by
//	the Free Software Foundation, either version 3 of the License, or
//	(at your option) any later version.
//
//	This program is distributed in the hope that it will be useful,
//	but WITHOUT ANY WARRANTY; without even the implied warranty of
//	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.See the
//	GNU General Public License for more details.
//
//	You should have received a copy of the GNU General Public License
//	along with this program.If not, see < https://www.gnu.org/licenses/>.
//-------------------------------------------------------------------

#include "InputHandling.h"
#include "Defines.h"

int main() {
	printf("\n                                   ");
	printf("\n            ---------              ");
	printf("\n           / .  '  . \\             ");
	printf("\n           -----------             ");
	printf("\n          < ~~~~~~~~~ >            ");
	printf("\n           -----------             ");
	printf("\n           \\. '  .  '/             ");
	printf("\n             -------               ");
	printf("\n    Welcome to MAC_Hunt3R 2.1.0    ");
	printf("\n                                   ");
	printf("\n Are you logged in as a DHCP admin?\n");

	initialiseDHCP();
	BOOL shouldExit = FALSE;
	while (shouldExit == FALSE)
	{
		char input      [INPUT_STRING_LENGTH]  = { 0 };
		char searchTerm [SEARCH_STRING_LENGTH] = { 0 };
		handleInput(input, searchTerm, INPUT_STRING_LENGTH);
	}
	cleanupDHCP();
    return ERROR_SUCCESS;
}
//	Copyright(C) 2023 Sean Bikkes, full license in MAC_Hunt3r2.c
