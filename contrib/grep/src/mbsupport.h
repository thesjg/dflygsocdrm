/* mbsupport.h --- Localize determination of whether we have multibyte stuff.

   Copyright (C) 2004-2005, 2007, 2009-2011 Free Software Foundation, Inc.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3, or (at your option)
   any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin Street - Fifth Floor, Boston, MA
   02110-1301, USA.  */


/* This file is needed so that we test for i18n support in just one place.
   This gives us a consistent definition for all uses of MBS_SUPPORT. This
   follows the ``Don't Repeat Yourself'' principle from "The Pragmatic
   Programmer".

   The tests should be *all* the ones that are needed for an individual
   application.  */

#include <stdlib.h>

#if defined HAVE_WCSCOLL && defined HAVE_ISWCTYPE
# define MBS_SUPPORT 1
#else
# define MBS_SUPPORT 0
#endif
