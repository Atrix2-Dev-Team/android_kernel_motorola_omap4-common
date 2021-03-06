/*
 * Copyright (C) 2011 Motorola, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
 * 02111-1307  USA
 */
#ifndef __LINUX_WRIGLEY_CTRL_H__
#define __LINUX_WRIGLEY_CTRL_H__

#ifdef __KERNEL__
#define WRIGLEY_CTRL_MODULE_NAME "wrigley_ctrl"

struct wrigley_ctrl_platform_data {
	char *name;
	unsigned int gpio_disable;
	unsigned int gpio_reset;
	unsigned int gpio_force_flash;
	unsigned int gpio_power_enable;
};

#endif
#endif /* __LINUX_WRIGLEY_CTRL_H__ */
