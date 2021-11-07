install:
	sudo chmod u+x scripts/install.sh
	cd scripts && ./install.sh && cd ..

uninstall:
	sudo chmod u+x scripts/uninstall.sh
	cd scripts && ./uninstall.sh && cd ..

clean:
	sudo chmod u+x scripts/uninstall.sh
	cd scripts && ./uninstall.sh && cd ..

start:
	sudo chmod u+x scripts/start.sh
	cd scripts && ./start.sh && cd ..

stop:
	sudo chmod u+x scripts/stop.sh
	cd scripts && ./stop.sh && cd ..

ui:
	sudo chmod u+x scripts/ui.sh
	cd scripts && ./ui.sh && cd ..

test:
	sudo chmod u+x scripts/test.sh
	cd scripts && ./test.sh && cd ..

help:
	sudo chmod u+x scripts/help.sh
	cd scripts && ./help.sh && cd ..
