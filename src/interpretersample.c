//Code Example C
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <math.h>

//Type definitions
typedef union {
	char  *s;
	char   c;
	float  f;
} arg_t;

typedef struct {
	const char* name;
	void (*func)(arg_t*);
	const char* args;
	const char* doc;
} cmd_t;

#define MK_CMD(x) void cmd_ ## x (arg_t*)
//Functions definitions
MK_CMD(prompt);
MK_CMD(load);
MK_CMD(disp);
MK_CMD(add);
MK_CMD(mul);
MK_CMD(sqrt);
MK_CMD(exit);
MK_CMD(help);

arg_t *args_parse(const char *s);

//The dispatch table
#define CMD(func, params, help) {#func, cmd_ ## func, params, help}

#define CMDS 8

cmd_t dsp_table[CMDS] ={
	CMD(prompt,"s","Select the prompt for input"),
	CMD(load,"cf","Load into register float"),
	CMD(disp,"c","Display register"),
	CMD(add,"ff","Add two numbers"),
	CMD(mul,"ff","Multiply two numbers"),
	CMD(sqrt,"f","Take the square root of number"),
	CMD(exit,"","Exits the interpreter"),
	CMD(help,"","Display this help")};

const char *delim = " \n(,);";
void parse(char *cmd)
{
	const char* tok = strtok(cmd,delim);
	if(!tok)
		return;

	int i=CMDS;
	while(i--) {
		cmd_t cur = dsp_table[i];
		if(!strcmp(tok,cur.name)) {
			arg_t *args = args_parse(cur.args);
			if(args==NULL && strlen(cur.args))
				return;//Error in argument parsing
			cur.func(args);
			free(args);
			return;
		}
	}

	puts("Command Not Found");
}

#define ESCAPE {free(args); puts("Bad Argument(s)"); return NULL;}
arg_t *args_parse(const char *s)
{
	int argc=strlen(s);
	arg_t *args=malloc(sizeof(arg_t)*argc);
	int i;
	for(i=0;i<argc;++i) {
		char *tok;
		switch(s[i]) {
		case 's':
			args[i].s = strtok(NULL,delim);
			if(!args[i].s)
				ESCAPE;
			break;
		case 'c':
			tok = strtok(NULL,delim);
			if(!tok)
				ESCAPE;
			args[i].c = tok[0];
			if(!islower(args[i].c))
				ESCAPE;
			break;
		case 'f':
			tok = strtok(NULL,delim);
			if(sscanf(tok,"%f", &args[i].f)!=1)
				ESCAPE;
			break;
		}
	}
	return args;
}
#undef ESCAPE

//Global data
char prompt[200];
float regs['z'-'a'];
void set_reg(char c, float f) {regs[c-'a'] = f;}
float get_reg(char c) {return regs[c-'a'];}

int main()
{
	char i;
	for(i='a';i<='z';++i)
		set_reg(i,0.0f);
	strncpy(prompt,">",200);

	//Read Parse Exec Loop
	char cmd[200];
	while(1) {
		printf("%s ",prompt);
		fflush(stdout);

		parse(fgets(cmd,200,stdin));
	}

	return 2;
}

void cmd_prompt(arg_t *args) {strncpy(prompt,args[0].s,200);}
void cmd_load(arg_t *args) {set_reg(args[0].c,args[1].f);}
void cmd_disp(arg_t *args) {printf("%f\n", get_reg(args[0].c));}
void cmd_add(arg_t *args) {printf("%f\n",args[0].f+args[1].f);}
void cmd_mul(arg_t *args) {printf("%f\n",args[0].f*args[1].f);}
void cmd_sqrt(arg_t *args) {printf("%f\n",sqrt(args[0].f));}
void cmd_exit(arg_t *args) {exit(0);}
void cmd_help(arg_t *args)
{
	puts("Available Commands:");
	int i=CMDS;
	while(i--) {
		cmd_t cmd=dsp_table[i];
		char tmp[100];//Formatting buffer
		snprintf(tmp,100,"%s(%s)",cmd.name,cmd.args);
		printf("%10s\t- %s\n",tmp,cmd.doc);
	}
}
