/*
 * =====================================================================================
 *
 *       Filename:  pcapdiff.c
 *
 *    Description:  
 *
 *        Version:  0.1
 *        Created:  07/14/2014 09:42:14 AM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  YOUR NAME (), 
 *   Organization:  
 *
 * =====================================================================================
 */

#include<stdlib.h>
#include<stdio.h>
#include<pcap/pcap.h>
#include<string.h>
#include<error.h>
int string_same(const char *s1,const char *s2,size_t n){
    size_t c=0;
    while((c!=n)&&(*s1==*s2)){
        ++s1;
        ++s2;
        ++c;
    }
    return (c==n)&&(c!=0)?1:0;
}

int main(int argc,char *argv[]){

    if (argc<4) {
        printf("\n-----------------------pcapdiff-----------------------\n");
        printf("-i : following two files need to compare .\n");
        printf("-o : the name of save-file  .\n");
        printf("-t : l2/l3/l4 .\n");
        printf("Exmaple 1: ./pcapdiff -i 1.pcap 2.pcap -o 3.pcap \n");
        printf("Exmaple 2: ./pcapdiff -t l2 -i 1.pcap 2.pcap -o 3.pcap \n\n");
        return 1;
	}

        char *filename1=NULL;
        char *filename2=NULL;
        char *filename3=NULL;
        int i;
        char *ln=NULL;
        int arg_length=0;
        char *arg=NULL;
        char x_layer=' ';        
        
        pcap_t *pcap1=NULL,*pcap2=NULL;
        char errbuf[PCAP_ERRBUF_SIZE];
        struct pcap_pkthdr *pkheader1=NULL,*pkheader2=NULL;
        u_char *pkdata1=NULL,*pkdata2=NULL;
        int ret1=0,ret2=0;
        int break_out=0; 
        int nsame_number=0;
        int number=0;
        
    for (i=1;i<argc;i++ ){
        arg=argv[i];
        arg_length=strlen(arg);

        if(arg_length==2&&arg[0]=='-'&&arg[1]!='-'){
            switch(arg[1]){
                case 't':
                    ln=argv[++i];
                    if((ln[0]=='l')&&((ln[1]=='2')||(ln[1]=='3')||(ln[1]=='4')))
                        x_layer=ln[1];
                    else{
                        fprintf(stderr,"Error; [ %s ] is not an option . \n",ln);
                    }
                break;
            
                case 'i':
                    filename1=argv[++i];
                    filename2=argv[++i];
                break;
                        
                case 'o':
                    filename3=argv[++i];
                break;
                        
                default:
                    fprintf(stderr,"Error; [ %s ] is not an option . \n",arg);
                    return 1;
                break;  
            }
        }
        else{
            filename1=argv[1];
            filename2=argv[2];
            filename3=argv[3];
        }
    }
    

/* 
    switch(x_layer){
        case ' ':
            pos_offset=0;
        break;
        case '2':
            pos_offset=14;
        break;
        case '3':
            pos_offset=34;
        break;
        case '4':
            pos_offset=42;
        break;
        default:
            fprintf(stderr,"Error; [ l%c ] is not an option . \n",x_layer);
    }
*/    
    pcap1=pcap_open_offline((const char *)filename1,errbuf);
    if(pcap1==NULL){
        fprintf(stderr,"ERROR: Can not open [ %s ] . \n",filename1);
        goto ERROR;
    }
    pcap_dumper_t *dumper=pcap_dump_open(pcap1,(const char *)filename3);
    if(dumper==NULL){
        fprintf(stderr,"ERROR: Can not get [ pcap_dumper_t *] . \n");
        goto ERROR;
    }

    while((ret1=pcap_next_ex(pcap1,&pkheader1,(const u_char **)&pkdata1))>=0){
        pcap2=pcap_open_offline((const char *)filename2,errbuf);
        if(pcap2==NULL){
            fprintf(stderr,"ERROR: Can not open [ %s ] . \n",filename2);
            goto ERROR;
        }
        
        while((ret2=pcap_next_ex(pcap2,&pkheader2,(const u_char **)&pkdata2))>=0){
            if(pkheader1->caplen > pkheader2->caplen){
                break_out=1;
                break;
            }
            else{
                if(string_same((const u_char *)pkdata1,(const u_char *)pkdata2,pkheader1->caplen)){
                    nsame_number-=1;
                    break_out=1;
                    break;
                }
                else{
                    nsame_number+=1;
                }    
            }
        }
        
        if(break_out==1){
            break_out=0;
            pcap_close(pcap2);
            pcap2=NULL;
            pkheader2=NULL;
            pkdata2=NULL;
        }
        
        if(nsame_number!=0){
            pcap_dump((u_char *)dumper,pkheader1,pkdata1);
            number+=1;     
        }
        
        if(ret2==-1){
            fprintf(stderr,"ERROR: %s . \n",pcap_geterr(pcap2));
            goto ERROR;
        }
        if(ret2==-2){
            pkheader1=NULL;
            pkdata1=NULL;            
        }
    }
    if(ret1==-1){
        fprintf(stderr,"ERROR: %s . \n",pcap_geterr(pcap1));
        goto ERROR;
    }
    if(ret1==-2){
    printf("there are %d packets . \n",number);
    }
ERROR:
    
    if(pcap1!=NULL){
        pcap_close(pcap1);
        pcap1=NULL;
    }
    if(dumper!=NULL){
        pcap_dump_close(dumper);
        dumper=NULL;
    }
    if(pcap2!=NULL){
        pcap_close(pcap2);
        pcap2=NULL;
    }
    
    return 0;
}
