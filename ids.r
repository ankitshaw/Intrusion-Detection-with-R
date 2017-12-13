library(caret)

data<-read.table("kddcup.data_10_percent_corrected.csv",sep = ",")

str(data)

colnames(data) = c("duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes", 
                   "land", "wrong_fragment", "urgent", "hot", "num_failed_logins", "logged_in", 
                   "num_compromised", "root_shell", "su_attempted", "num_root", "num_file_creations", 
                   "num_shells", "num_access_files", "num_outbound_cmds", "is_hot_login",
                   "is_guest_login", "count", "srv_count", "serror_rate", "srv_serror_rate", 
                   "rerror_rate","srv_rerror_rate", "same_srv_rate", "diff_srv_rate",                        
                   "srv_diff_host_rate", "dst_host_count","dst_host_srv_count","dst_host_same_srv_rate", 
                   "dst_host_diff_srv_rate", "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate", 
                   "dst_host_serror_rate","dst_host_srv_serror_rate", "dst_host_rerror_rate", "dst_host_srv_rerror_rate", 
                   "result")


# Preprocessing the data
data$duration = as.numeric(as.character(data$duration))
data$protocol_type = factor(data$protocol_type)
data$service = factor(data$service)
data$flag = factor(data$flag)
data$src_bytes = as.numeric(as.character(data$src_bytes))
data$dst_bytes = as.numeric(as.character(data$dst_bytes))
data$land = factor(data$land)
data$wrong_fragment = as.numeric(as.character(data$wrong_fragment))
data$urgent = as.numeric(as.character(data$urgent))
data$hot = as.numeric(as.character(data$hot))
data$num_failed_logins = as.numeric(as.character(data$num_failed_logins))
data$logged_in = factor(data$logged_in)
data$num_compromised = as.numeric(as.character(data$num_compromised))
data$root_shell = factor(data$root_shell)
data$su_attempted = factor(data$su_attempted)
data$num_root = as.numeric(as.character(data$num_root))
data$num_file_creations = as.numeric(as.character(data$num_file_creations))
data$num_shells = as.numeric(as.character(data$num_shells))
data$num_access_files = as.numeric(as.character(data$num_access_files))
# data$num_outbound_cmds = as.numeric(as.character(data$num_outbound_cmds))
# data$is_hot_login = factor(data$is_hot_login)
data$is_guest_login = factor(data$is_guest_login)
data$count = as.numeric(as.character(data$count))
data$srv_count = as.numeric(as.character(data$srv_count))
data$serror_rate = as.numeric(as.character(data$serror_rate))
data$srv_serror_rate = as.numeric(as.character(data$srv_serror_rate))
data$rerror_rate = as.numeric(as.character(data$rerror_rate))
data$srv_rerror_rate = as.numeric(as.character(data$srv_rerror_rate))
data$same_srv_rate = as.numeric(as.character(data$same_srv_rate))
data$diff_srv_rate = as.numeric(as.character(data$diff_srv_rate))
data$srv_diff_host_rate = as.numeric(as.character(data$srv_diff_host_rate))
data$dst_host_count = as.numeric(as.character(data$dst_host_count))
data$dst_host_srv_count = as.numeric(as.character(data$dst_host_srv_count))
data$dst_host_same_srv_rate = as.numeric(as.character(data$dst_host_same_srv_rate))
data$dst_host_diff_srv_rate = as.numeric(as.character(data$dst_host_diff_srv_rate))
data$dst_host_same_src_port_rate = as.numeric(as.character(data$dst_host_same_src_port_rate))
data$dst_host_srv_diff_host_rate = as.numeric(as.character(data$dst_host_srv_diff_host_rate))
data$dst_host_serror_rate = as.numeric(as.character(data$dst_host_serror_rate))
data$dst_host_srv_serror_rate = as.numeric(as.character(data$dst_host_srv_serror_rate))
data$dst_host_rerror_rate = as.numeric(as.character(data$dst_host_rerror_rate))
data$dst_host_srv_rerror_rate = as.numeric(as.character(data$dst_host_srv_rerror_rate))

#DOS: denial-of-service, e.g. syn flood;
#R2L: unauthorized access from a remote machine, e.g. guessing password;
#U2R:  unauthorized access to local superuser (root) privileges, e.g., various ``buffer overflow'' attacks;
#probing: surveillance and other probing, e.g., port scanning.

data$result = as.character(data$result)
data$result[data$result == "ipsweep."] = "probe"
data$result[data$result == "portsweep."] = "probe"
data$result[data$result == "nmap."] = "probe"
data$result[data$result == "satan."] = "probe"
data$result[data$result == "buffer_overflow."] = "u2r"
data$result[data$result == "loadmodule."] = "u2r"
data$result[data$result == "perl."] = "u2r"
data$result[data$result == "rootkit."] = "u2r"
data$result[data$result == "back."] = "dos"
data$result[data$result == "land."] = "dos"
data$result[data$result == "neptune."] = "dos"
data$result[data$result == "pod."] = "dos"
data$result[data$result == "smurf."] = "dos"
data$result[data$result == "teardrop."] = "dos"
data$result[data$result == "ftp_write."] = "r2l"
data$result[data$result == "guess_passwd."] = "r2l"
data$result[data$result == "imap."] = "r2l"
data$result[data$result == "multihop."] = "r2l"
data$result[data$result == "phf."] = "r2l"
data$result[data$result == "spy."] = "r2l"
data$result[data$result == "warezclient."] = "r2l"
data$result[data$result == "warezmaster."] = "r2l"
data$result[data$result == "normal."] = "normal"
data$result = as.factor(data$result)


library(corrplot)
data2 <- data[,5:41]
colnames(data2) <- NULL
correlation <- cor(data2)
corrplot(correlation, method="circle", na.label= '.')


# Observation: dst_host_same_src_port_rate has slight effect on the intrusion type.
# for "dst_host_same_src_port_rate" value greater than equal to 1 it can be "probe" and "r2l""
qplot(dst_host_same_src_port_rate,dst_host_srv_diff_host_rate,colour=result,data=data)

# Observation: "flag" is a strong predictor. for flag= "REG" and "S0" it is "dos"
qplot(service,flag,colour=result,data=data)

# Observation: For duration Greater than 30000 we can see it's 'probe'
# Therefore duration itself is a strong predictor
x <- qplot(duration,src_bytes,colour=result,data=data)

# Observation: protocol-type "tcp" has "DOS" intrusion type. It is also a strong predictor of "dos" type.
qplot(service,protocol_type,colour=result,data=data)

# Observation: No such clear identification
qplot(flag,land,colour=result,data=data)

# Observation: For serror_rate and srv_serror_rate=0 or 1 its "dos" and
# serror_rate between 0.25 to 0.5 its "probe""
qplot(serror_rate,srv_serror_rate,colour=result,data=data)

# Observation:For duration Greater than 30000 we can see it's 'probe'
qplot(duration,src_bytes,colour=result,data=data)

# Result: We can clearly see flag is a strong predictor for "dos" type intrusion
A=table(data$flag,data$result)
round(prop.table(A)*100,1)

## Model

library(randomForest)
control <- rfeControl(functions=rfFuncs, method="cv", number=10)
data1<-data[,c("srv_rerror_rate",   "rerror_rate", "flag","dst_host_rerror_rate" ,  
               "logged_in" ,"dst_bytes","src_bytes","num_compromised" ,           
               "dst_host_srv_count","duration" ,"dst_host_same_src_port_rate","dst_host_diff_srv_rate" ,   
               "dst_host_count","dst_host_srv_serror_rate","count","hot" ,                      
               "dst_host_same_srv_rate","dst_host_srv_diff_host_rate" ,"dst_host_serror_rate" ,"serror_rate",                
               "srv_serror_rate" ,"diff_srv_rate","srv_count","srv_diff_host_rate","protocol_type","result" )] 
inTrain <- createDataPartition(y=data1$result,p=0.02, list=FALSE)
training <- data1[inTrain,]
testing <- data1[-inTrain,]
dim(training)


## Training

modFit <- train(result ~ .,method="rf",data=training)
modFit
getTree(modFit$finalModel,k=2)


## Prediction

pred <- predict(modFit,testing); 
testing$predRight <- pred==testing$result
table(pred,testing$result)

A=table(pred,testing$result)
round(prop.table(A,1)*100,2)
