/* kernel/power/userwakelock.c
 *
 * Copyright (C) 2005-2008 Google, Inc.
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */

#include <linux/ctype.h>
#include <linux/module.h>
#include <linux/wakelock.h>
#include <linux/slab.h>

#include "power.h"

enum {
	DEBUG_FAILURE	= BIT(0),
	DEBUG_ERROR	= BIT(1),
	DEBUG_NEW	= BIT(2),
	DEBUG_ACCESS	= BIT(3),
	DEBUG_LOOKUP	= BIT(4),
};
static int debug_mask = DEBUG_FAILURE;
module_param_named(debug_mask, debug_mask, int, S_IRUGO | S_IWUSR | S_IWGRP);

static DEFINE_MUTEX(tree_lock_blacklist);

struct owner_name{
	struct owner_name * next;
	char name[0];
};

struct wakelock_blacklist {
	struct rb_node		node;
	struct owner_name 	*owner;
	char			name[0];
};

struct rb_root wakelock_blacklists;

static struct wakelock_blacklist *lookup_blacklist_wakelock_name(
	const char *buf,int allocate, int matchmode)
{
	struct rb_node **p = &wakelock_blacklists.rb_node;
	struct rb_node *parent = NULL;
	struct wakelock_blacklist *l;
	struct owner_name *po,*own_item,*po_last;
	int diff,rm_node=0,ownDeleted=0,found_wakelock=0;
	
	int name_len,own_len;
	const char *arg,*begin,*own=NULL;

	/* Find length of lock name */
	for (arg = buf; *arg; arg++){
		if ((*arg) == '-'){
			if (allocate)
				rm_node = 1;
			continue;
		}
		if (!isspace(*arg))
			break;
	}
	begin=arg;
	while ((*arg) && !isspace(*arg) && ((*arg) != ':'))
		arg++;
	name_len = arg - begin;
	if (!name_len)
		goto bad_arg;

	while (isspace(*arg) || ((*arg) == ':')){
		if ((*arg) == ':'){
			own=arg;
		}
		arg++;
	}
	if (own)
		own = arg;

	/* Lookup blacklist item in rbtree */
	while (*p) {
		parent = *p;
		l = rb_entry(parent, struct wakelock_blacklist, node);
		diff = strncmp(begin, l->name, name_len);
		if (!diff && l->name[name_len])
			diff = -1;
		if (debug_mask & DEBUG_ERROR)
			pr_info("lookup_blacklist_wakelock_name: compare %.*s %s %d\n",
				name_len, buf, l->name, diff);
		if (diff < 0)
			p = &(*p)->rb_left;
		else if (diff > 0)
			p = &(*p)->rb_right;
		else{
			found_wakelock = 1;
			break;
		}
	}
	if(!found_wakelock){
		if(!allocate || rm_node)
			return ERR_PTR(-EINVAL);
		l = kzalloc(sizeof(*l) + name_len + 1, GFP_KERNEL);
		if (l == NULL) {
			if (debug_mask & DEBUG_FAILURE)
				pr_err("lookup_blacklist_wakelock_name: failed to allocate "
					"memory for %.*s\n", name_len, buf);
			return ERR_PTR(-ENOMEM);
		}
		memcpy(l->name, begin, name_len);
		if (debug_mask & DEBUG_NEW)
			pr_info("lookup_blacklist_wakelock_name: new blacklist wakelock %s\n", l->name);
		rb_link_node(&l->node, parent, p);
		rb_insert_color(&l->node, &wakelock_blacklists);
	}
	while (*arg && own){
		while (isspace(*own))
			own++;
		arg=own;
		while((*arg) && !isspace(*arg) && (*arg) != ',' )
			arg++;
		own_len = arg - own;
		po = l->owner;
		diff = -1;
		po_last=po;
		while (po && diff){
			diff = strncmp(po->name, own, own_len);
			if (!diff && own[own_len])
				diff = -1;
			if (diff != 0){
				po_last = po;
				po = po->next;
			}
		}
		if (diff != 0){
			if(!allocate || rm_node)
				return ERR_PTR(-EINVAL);
			if(matchmode && !l->owner)
				return l;
			own_item = kzalloc(sizeof(*own_item) + own_len + 1, GFP_KERNEL);
			if (own_item == NULL){
				if (debug_mask & DEBUG_FAILURE)
					pr_err("lookup_blacklist_wakelock_name: failed to allocate "
						"memory for %.*s\n",own_len,own);
				return ERR_PTR(-ENOMEM);
			}
			memcpy(own_item->name,own,own_len);
			po = l->owner;
			while(po && po->next)
				po = po->next;
			if (!po)
				l->owner = own_item;
			else
				po->next = own_item;
		}
		else if (rm_node){	//if found and need to delete it
			if (po == l->owner)
				l->owner = po->next;
			else
				po_last->next = po->next;
			kfree(po);
			ownDeleted = 1;
		}
		while((*arg) && (*arg) != ',')
			arg++;
		if((*arg) != ',')
			break;
		else
			arg++;
	}
	if(!own && rm_node){
		kfree(l);
		rb_erase(*p,&wakelock_blacklists);
		return NULL;
	}
	return l;

bad_arg:
	if (debug_mask & DEBUG_ERROR)
		pr_info("lookup_blacklist_wakelock_name: wakelock(%.*s), bad arg(%s)\n",
			name_len, buf, arg);
	return ERR_PTR(-EINVAL);
}

ssize_t wakelock_blacklist_show(
	struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	char *s = buf;
	char *end = buf + PAGE_SIZE;
	struct rb_node *n;
	struct wakelock_blacklist *l;
	struct owner_name *o;

	mutex_lock(&tree_lock_blacklist);

	for (n = rb_first(&wakelock_blacklists); n != NULL; n = rb_next(n)) {
		l = rb_entry(n, struct wakelock_blacklist, node);
		s += scnprintf(s, end - s, "%s ", l->name);
		o = l->owner;
		if (o && o->name)
			s += scnprintf(s, end - s, " : ");
		while(o){
			s += scnprintf(s, end - s, "%s ",o->name);
			o = o->next;
		}
		s += scnprintf(s, end - s, "\n");
	}

	mutex_unlock(&tree_lock_blacklist);
	return (s - buf);
}

ssize_t wakelock_blacklist_store(
	struct kobject *kobj, struct kobj_attribute *attr,
	const char *buf, size_t n)
{
	struct wakelock_blacklist *l;

	mutex_lock(&tree_lock_blacklist);
	l = lookup_blacklist_wakelock_name(buf, 1, 0);
	if (IS_ERR(l)) {
		n = PTR_ERR(l);
		goto bad_name;
	}

	if (debug_mask & DEBUG_ACCESS && l)
		pr_info("wakelock_blacklist_store: %s\n", l->name);

bad_name:
	mutex_unlock(&tree_lock_blacklist);
	return n;
}

ssize_t wakelock_blacklist_match(const char * buf)
{
	struct wakelock_blacklist *l;
	l = lookup_blacklist_wakelock_name(buf,0,1);
	if (!IS_ERR(l)){
		if (debug_mask & DEBUG_ACCESS)
			pr_info("wakelock_blacklist_match: %s (matched)\n",buf);
		return 1;
	}
	if (debug_mask & DEBUG_ACCESS)
		pr_info("wakelock_blacklist_match: %s (not match)\n",buf);
	return 0;
}

