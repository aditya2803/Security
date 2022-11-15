#include<linux/lsm_hooks.h>
#include<linux/kern_levels.h>
#include<linux/binfmts.h>
#include<linux/fs.h>
struct Node {
	int id;
	char label[100];
	struct Node* next;
};

struct Mapping {
	long long oldId;
	long long newId;
};

struct Mapping* mappingArray = NULL;
struct Node** graph = NULL;

/*
 * Function to get new id from old id, using the mapping file
 * 
*/
long long getMapping(long long id) {
	int i = 0;
	for(i = 0; i < 10000; i++) {
		if(mappingArray[i].oldId == id)
			return mappingArray[i].newId;
	}
	return -1;
}

/*
 * Example DOT file:
 *	1;
 *	2:
 *	3;
 *	4;
 *	1 -> 2 [label='read'];
 *	2 -> 3 [label='epsilon'];
 *	1 -> 3 [label='epsilon'];
 *
*/

struct Node* loadCFG(struct file* file) {
	char content;
	long long offset = 0;
	long long count = 0;
	bool edges = false;
	bool exit = false;
	int i = 0;
	long nodeVal = 0;
	long sNode = 0;
	long dNode = 0;
	int ret = 0;
	int newNodeId = 0;
	mappingArray = kmalloc(sizeof(struct Mapping) * 10000, GFP_ATOMIC);
	printk("LOADING THE CFG!!!!!");
	while(kernel_read(file, &content, 1, &offset) > 0) {
		if(content == '\n') {
			count += 1;
		}
		else if(count >= 3) {
			char *node = kmalloc(100, GFP_ATOMIC);
			//Started reading a line and got a new node
			node[i] = content;
			if(content == '}') {
				exit = true;
				break;
			}
			i++;
			while(kernel_read(file, &content, 1, &offset) > 0) {
				//Read this line
				if(content == ';') {
					break;
				}
				if(content == '-') {
					edges = true;
				}
				if(content == '}') {
					exit = true;
				}
				node[i] = content;
				i++;
			}
			if(exit) {
				break;
			}
			node[i] = '\0';
			i = 0;
			if(edges) {
				struct Node* begin;
				char* token = strsep((&node), " ");
				char label[100];
				int j = 0;
				//Initialize a graph (Adj List) of struct Nodes', having size equal to number of nodes
				if(graph == NULL) {
					graph = kmalloc(sizeof(struct Node*) * newNodeId, GFP_ATOMIC);
					for(j = 0; j < newNodeId; j++) {
						graph[j] = NULL;
					}
				}
				ret = kstrtol(token, 10, &sNode);
        			token = strsep(&node, " ");
				token = strsep(&node, " ");
				ret = kstrtol(token, 10, &dNode);
				token = strsep(&node, " ");
				token = strsep(&node, " ");
				//Get mapping of sNode
				sNode = getMapping(sNode);
				//Get mapping of dNode
				dNode = getMapping(dNode);
				//add edge from sNodeMapping to dNodeMapping
				for(j = 7; token[j] != ']'; j++)
					label[j - 7] = token[j];
				label[j - 7] = '\0';
				begin = graph[sNode];
				if(begin == NULL) {
					graph[sNode] = kmalloc(sizeof(struct Node), GFP_ATOMIC);
					graph[sNode]->id = dNode;
					strcpy(graph[sNode]->label, label);
					graph[sNode]->next = NULL;
				}
				else {
					while(begin->next != NULL) {
						begin = begin->next;
					}
					begin->next = kmalloc(sizeof(struct Node), GFP_ATOMIC);
					begin->next->id = dNode;
					strcpy(begin->next->label, label);
					begin->next->next = NULL;
				}
			}
			else {
				struct Mapping *newMapping;
				newMapping = kmalloc(sizeof(struct Mapping), GFP_ATOMIC);
				ret = kstrtol(node, 10, &nodeVal);
				newMapping->oldId = nodeVal;
				newMapping->newId = newNodeId;
				mappingArray[newNodeId] = *newMapping;
				printk("Got a new node: %ld\n", nodeVal);
				newNodeId += 1;
			}
		}
	}
	/*
	 * Print the adjacency matrix
	*/ 
	for(i = 0; i < newNodeId; i++) {
		struct Node* temp;
		printk("Parent: %d\n", i);
	        temp = graph[i];
		if(temp == NULL)
			continue;
		while(temp != NULL) {
			printk("%d %s\n", temp->id, temp->label);
			temp = temp->next;
		}
	}
	return NULL;
}

static int my_module_task_check_security(struct linux_binprm *bprm) {
	char dotFilePath[100];
	char modifiedExecPath[100];
	int i = 0;
	struct file *file;
	struct Node* root;
	strcpy(modifiedExecPath, bprm->interp);
	for(i = 0; modifiedExecPath[i] != '\0'; i++) {
		if(modifiedExecPath[i] == '/')
			modifiedExecPath[i] = '_';
	}
	printk("File Path: %s\n", bprm->interp);
	printk("Modified Path: %s\n", modifiedExecPath);
	strcpy(dotFilePath, "/root/");
	strcat(dotFilePath, modifiedExecPath);	
	strcat(dotFilePath, "_CFG.dot");
        file = filp_open(dotFilePath, O_RDONLY, 0);
	if (IS_ERR(file))
		printk("No dotfile for %s\n", dotFilePath);
	else {
		printk("Dotfile for %s\n", dotFilePath);
	        root = loadCFG(file);
	}
	printk("Dot File Name: %s\n", dotFilePath);
	return 0;
}

static struct security_hook_list my_module_hooks[] __lsm_ro_after_init = {
	LSM_HOOK_INIT(bprm_creds_for_exec, my_module_task_check_security),
};

static int __init my_module_init(void) {
	printk(KERN_ERR "mymodule: We are going to do things\n");
	security_add_hooks(my_module_hooks, ARRAY_SIZE(my_module_hooks), "my_module");
	return 0;
}

DEFINE_LSM(yama) = {
	.name = "my_module",
	.init = my_module_init,
};
