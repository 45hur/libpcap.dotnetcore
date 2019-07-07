FROM mcr.microsoft.com/dotnet/core/sdk:2.2 AS build-env

RUN mkdir /app
WORKDIR /app

COPY /*.sln ./
COPY /src/*.csproj ./src/
RUN dotnet restore

RUN dotnet new global.json

COPY / ./
RUN dotnet publish ./libpcap.dotnetcore.sln -c Release -o out

FROM mcr.microsoft.com/dotnet/core/sdk:2.2-alpine
WORKDIR /app
COPY --from=build-env /app/src/out .

RUN apk add libcap
RUN apk add libpcap-dev
RUN apk add tshark

ENTRYPOINT ["dotnet", "libpcap.dotnetcore.dll"]
