#
# Copyright (c) 2012 Brian Kloppenborg
#
# This file is part of the Path Finding Library (PathFind).
#  
#  PathFind is free software: you can redistribute it and/or modify
#  it under the terms of the GNU Lesser General Public License 
#  as published by the Free Software Foundation, either version 3 
#  of the License, or (at your option) any later version.
#  
#  PathFind is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU Lesser General Public License for more details.
#  
#  You should have received a copy of the GNU Lesser General Public 
#  License along with LIBOI.  If not, see <http://www.gnu.org/licenses/>.


cmake_minimum_required(VERSION 2.8)
project(pathfind)

file(GLOB SOURCE *.cpp )

add_library(pathfind SHARED EXCLUDE_FROM_ALL ${SOURCE})

add_library(pathfind_static STATIC ${SOURCE})

install(TARGETS pathfind_static DESTINATION lib)
install(FILES pathfind.hpp DESTINATION include)
